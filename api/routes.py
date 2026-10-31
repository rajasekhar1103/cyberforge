from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import logging
import re
import uuid
from typing import Any

import duckdb
from fastapi import APIRouter, Query, Request

from api.errors import ApiError, DataIntegrityError, invalid_parameter
from api.service import AnalyticsService, decode_json_field, row_dicts

logger = logging.getLogger("cyberforge.api")
router = APIRouter(prefix="/api")
SEVERITIES = ("low", "medium", "high", "critical")
NODE_TYPES = ("ip", "user", "host", "technique", "detection", "incident")
HUGEINT_MAX = 170141183460469231731687303715884105727
INCIDENT_JSON_FIELDS = (
    "related_srcips",
    "related_dstips",
    "related_usernames",
    "related_hosts",
    "detection_ids",
    "correlation_reasons",
    "evidence_refs",
)
DETECTION_JSON_FIELDS = ("evidence", "matched_conditions", "mitre_techniques")


def _service(request: Request) -> AnalyticsService:
    return request.app.state.analytics


def _path(service: AnalyticsService, store: str) -> str:
    return str(getattr(service.config, f"{store}_path"))


def _validate_uuid(value: str, parameter: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise invalid_parameter(f"{parameter} must be a canonical UUID", parameter) from exc
    if str(parsed) != value:
        raise invalid_parameter(f"{parameter} must be a canonical UUID", parameter)
    return value


def _validate_time(value: str | None, parameter: str) -> str | None:
    if value is None:
        return None
    if not 1 <= len(value) <= 38 or not value.isascii() or not value.isdigit():
        raise invalid_parameter(f"{parameter} must contain 1 to 38 decimal digits", parameter)
    if int(value) > HUGEINT_MAX:
        raise invalid_parameter(f"{parameter} exceeds the supported timestamp range", parameter)
    return value


def _validate_page(limit: int, offset: int, maximum: int, cursor: str | None) -> None:
    if not 1 <= limit <= maximum:
        raise invalid_parameter(f"limit must be between 1 and {maximum}", "limit")
    if not 0 <= offset <= 10_000:
        raise invalid_parameter("offset must be between 0 and 10000", "offset")
    if cursor is not None and offset != 0:
        raise invalid_parameter("cursor and non-zero offset cannot be used together", "cursor")


def _encode_cursor(service: AnalyticsService, endpoint: str, key: dict[str, Any]) -> str:
    payload = {
        "version": 1,
        "endpoint": endpoint,
        "generation": service.dataset_generation(),
        "key": key,
    }
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_cursor(
    service: AnalyticsService,
    cursor: str | None,
    endpoint: str,
) -> dict[str, Any] | None:
    if cursor is None:
        return None
    if not 1 <= len(cursor) <= 2048:
        raise invalid_parameter("cursor has an invalid length", "cursor")
    try:
        raw = base64.b64decode(
            cursor + "=" * (-len(cursor) % 4),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
        raise invalid_parameter("cursor is malformed", "cursor") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or payload.get("endpoint") != endpoint
        or payload.get("generation") != service.dataset_generation()
        or not isinstance(payload.get("key"), dict)
    ):
        raise invalid_parameter("cursor is invalid or belongs to a different dataset", "cursor")
    return payload["key"]


def _validate_cursor_time(value: Any, parameter: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise invalid_parameter("cursor timestamp is malformed", parameter)
    try:
        return _validate_time(value, parameter)
    except ApiError as exc:
        raise invalid_parameter("cursor timestamp is malformed", parameter) from exc


def _validate_stored_timestamp(value: Any, field: str) -> None:
    if value is None:
        return
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 38
        or not value.isascii()
        or not value.isdigit()
        or int(value) > HUGEINT_MAX
    ):
        raise DataIntegrityError(
            f"Stored timestamp field {field} is not valid decimal eventtime text",
            {"field": field},
        )


def _decode_incident(row: dict[str, Any]) -> dict[str, Any]:
    _validate_stored_timestamp(row.get("first_observed"), "first_observed")
    _validate_stored_timestamp(row.get("last_observed"), "last_observed")
    for field in INCIDENT_JSON_FIELDS:
        decode_json_field(row, field, list)
    return row


def _decode_detection(row: dict[str, Any]) -> dict[str, Any]:
    _validate_stored_timestamp(row.get("eventtime"), "eventtime")
    for field in DETECTION_JSON_FIELDS:
        expected = dict if field == "evidence" else list
        decode_json_field(row, field, expected)
    return row


def _one_or_missing(
    connection: duckdb.DuckDBPyConnection,
    sql: str,
    params: list[Any],
    entity: str,
) -> dict[str, Any]:
    cursor = connection.execute(sql, params)
    rows = row_dicts(cursor)
    if not rows:
        raise ApiError(404, "not_found", f"{entity} was not found")
    if len(rows) > 1:
        raise DataIntegrityError(f"Stored {entity} ID is not unique")
    return rows[0]


def _verify_incident_relationships(
    connection: duckdb.DuckDBPyConnection,
    service: AnalyticsService,
    incident_id: str,
) -> int:
    relation_path = _path(service, "incident_detections")
    detection_path = _path(service, "detections")
    counts = connection.execute(
        """
        SELECT count(*) AS relation_count,
               count(DISTINCT detection_id) AS distinct_count
        FROM read_parquet(?) WHERE incident_id = ?
        """,
        [relation_path, incident_id],
    ).fetchone()
    relation_count, distinct_count = counts
    joined_count = connection.execute(
        """
        SELECT count(*)
        FROM read_parquet(?) r
        JOIN read_parquet(?) d USING (detection_id)
        WHERE r.incident_id = ?
        """,
        [relation_path, detection_path, incident_id],
    ).fetchone()[0]
    if relation_count != distinct_count or relation_count != joined_count:
        missing_ids = [
            row[0]
            for row in connection.execute(
                """
                SELECT r.detection_id
                FROM read_parquet(?) r
                LEFT JOIN read_parquet(?) d USING (detection_id)
                WHERE r.incident_id = ? AND d.detection_id IS NULL
                LIMIT 20
                """,
                [relation_path, detection_path, incident_id],
            ).fetchall()
        ]
        logger.error(
            "Broken incident-to-detection relation for incident %s; missing IDs: %s",
            incident_id,
            missing_ids,
        )
        raise DataIntegrityError(
            "Incident-to-detection relationships are inconsistent",
            {"missing_detection_ids": missing_ids},
        )
    return relation_count


def _pagination(limit: int, offset: int, total: int, next_cursor: str | None) -> dict[str, Any]:
    return {
        "limit": limit,
        "offset": offset,
        "total": total,
        "next_cursor": next_cursor,
    }


@router.get("/health")
async def health(request: Request) -> dict[str, Any]:
    await _service(request).check_stores()
    return {
        "status": "ok",
        "service": "cyberforge-api",
        "stores": {
            "detections": "ready",
            "incidents": "ready",
            "incident_detections": "ready",
            "graph": "ready",
        },
    }


@router.get("/summary")
async def summary(request: Request) -> dict[str, Any]:
    service = _service(request)
    detections_path = _path(service, "detections")
    incidents_path = _path(service, "incidents")
    relations_path = _path(service, "incident_detections")

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        detection_total = connection.execute(
            "SELECT count(*) FROM read_parquet(?)", [detections_path]
        ).fetchone()[0]
        incident_total = connection.execute(
            "SELECT count(*) FROM read_parquet(?)", [incidents_path]
        ).fetchone()[0]
        unassigned = connection.execute(
            """
            SELECT count(*)
            FROM read_parquet(?) d
            WHERE NOT EXISTS (
                SELECT 1 FROM read_parquet(?) r
                WHERE r.detection_id = d.detection_id
            )
            """,
            [detections_path, relations_path],
        ).fetchone()[0]
        broken_count = connection.execute(
            """
            SELECT count(*)
            FROM read_parquet(?) r
            LEFT JOIN read_parquet(?) d USING (detection_id)
            WHERE d.detection_id IS NULL
            """,
            [relations_path, detections_path],
        ).fetchone()[0]
        if broken_count:
            raise DataIntegrityError(
                "Incident-to-detection relationships reference missing detections",
                {"broken_relationship_count": broken_count},
            )

        def severity_counts(path: str, name: str) -> dict[str, int]:
            counts = {severity: 0 for severity in SEVERITIES}
            for severity, count in connection.execute(
                f"SELECT severity, count(*) FROM read_parquet(?) GROUP BY severity",
                [path],
            ).fetchall():
                if severity not in counts:
                    raise DataIntegrityError(
                        f"Stored {name} severity is outside the API contract",
                        {"severity": severity},
                    )
                counts[severity] = count
            return counts

        categories: dict[str, int] = {}
        for category, count in connection.execute(
            "SELECT category, count(*) FROM read_parquet(?) GROUP BY category",
            [detections_path],
        ).fetchall():
            if not isinstance(category, str) or not category:
                raise DataIntegrityError("Stored detection category is null or empty")
            categories[category] = count

        return {
            "total_detections": detection_total,
            "total_incidents": incident_total,
            "unassigned_detections": unassigned,
            "detections_by_severity": severity_counts(detections_path, "detection"),
            "incidents_by_severity": severity_counts(incidents_path, "incident"),
            "detections_by_category": categories,
        }

    return await service.run(query)


@router.get("/incidents")
async def incidents(
    request: Request,
    severity: str | None = None,
    srcip: str | None = None,
    username: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    limit: int = 50,
    offset: int = 0,
    cursor: str | None = None,
) -> dict[str, Any]:
    service = _service(request)
    _validate_page(limit, offset, 200, cursor)
    if severity is not None and severity not in SEVERITIES:
        raise invalid_parameter("severity must be low, medium, high, or critical", "severity")
    if srcip is not None:
        try:
            ipaddress.ip_address(srcip)
        except ValueError as exc:
            raise invalid_parameter("srcip must be a valid IPv4 or IPv6 address", "srcip") from exc
    if username is not None and (not username or len(username) > 256):
        raise invalid_parameter("username must contain 1 to 256 characters", "username")
    start_time = _validate_time(start_time, "start_time")
    end_time = _validate_time(end_time, "end_time")
    if start_time is not None and end_time is not None and int(start_time) > int(end_time):
        raise invalid_parameter("start_time must not exceed end_time", "start_time")
    cursor_key = _decode_cursor(service, cursor, "incidents")
    cursor_time = None
    cursor_id = None
    if cursor_key is not None:
        cursor_time = _validate_cursor_time(cursor_key.get("first_observed"), "cursor")
        cursor_id = cursor_key.get("incident_id")
        if not isinstance(cursor_id, str):
            raise invalid_parameter("cursor is malformed", "cursor")
        _validate_uuid(cursor_id, "cursor")

    incident_path = _path(service, "incidents")
    relation_path = _path(service, "incident_detections")
    detection_path = _path(service, "detections")
    conditions: list[str] = []
    filter_params: list[Any] = []
    if severity is not None:
        conditions.append("i.severity = ?")
        filter_params.append(severity)
    detection_conditions: list[str] = []
    detection_params: list[Any] = []
    if srcip is not None:
        detection_conditions.append("d.srcip = ?")
        detection_params.append(srcip)
    if username is not None:
        detection_conditions.append("d.username = ?")
        detection_params.append(username)
    if start_time is not None:
        detection_conditions.append("TRY_CAST(d.eventtime AS HUGEINT) >= CAST(? AS HUGEINT)")
        detection_params.append(start_time)
    if end_time is not None:
        detection_conditions.append("TRY_CAST(d.eventtime AS HUGEINT) <= CAST(? AS HUGEINT)")
        detection_params.append(end_time)
    if detection_conditions:
        conditions.append(
            "EXISTS (SELECT 1 FROM read_parquet(?) r "
            "JOIN read_parquet(?) d USING (detection_id) "
            "WHERE r.incident_id = i.incident_id AND "
            + " AND ".join(detection_conditions)
            + ")"
        )
        filter_params.extend([relation_path, detection_path, *detection_params])

    base = f"FROM read_parquet(?) i"
    base_params: list[Any] = [incident_path, *filter_params]
    if conditions:
        base += " WHERE " + " AND ".join(conditions)

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        total = connection.execute(f"SELECT count(*) {base}", base_params).fetchone()[0]
        page_condition = ""
        page_params: list[Any] = []
        if cursor_key is not None:
            if cursor_time is None:
                page_condition = (
                    "TRY_CAST(i.first_observed AS HUGEINT) IS NULL "
                    "AND i.incident_id > ?"
                )
                page_params = [cursor_id]
            else:
                page_condition = (
                    "(TRY_CAST(i.first_observed AS HUGEINT) < CAST(? AS HUGEINT) "
                    "OR TRY_CAST(i.first_observed AS HUGEINT) IS NULL "
                    "OR (TRY_CAST(i.first_observed AS HUGEINT) = CAST(? AS HUGEINT) "
                    "AND i.incident_id > ?))"
                )
                page_params = [cursor_time, cursor_time, cursor_id]
        page_where = ""
        if page_condition:
            page_where = (" AND " if conditions else " WHERE ") + page_condition
        sql = (
            f"SELECT i.* {base}{page_where} "
            "ORDER BY TRY_CAST(i.first_observed AS HUGEINT) DESC NULLS LAST, i.incident_id ASC "
            "LIMIT ? OFFSET ?"
        )
        page = row_dicts(
            connection.execute(sql, [*base_params, *page_params, limit + 1, offset])
        )
        has_more = len(page) > limit
        page = page[:limit]
        items = [_decode_incident(row) for row in page]
        next_cursor = None
        if has_more and page:
            last = page[-1]
            _validate_stored_timestamp(last.get("first_observed"), "first_observed")
            next_cursor = _encode_cursor(
                service,
                "incidents",
                {"first_observed": last.get("first_observed"), "incident_id": last["incident_id"]},
            )
        return {
            "items": items,
            "pagination": _pagination(limit, offset, total, next_cursor),
        }

    return await service.run(query)


async def _incident_page(
    request: Request,
    incident_id: str,
    limit: int,
    offset: int,
    cursor: str | None,
    *,
    timeline: bool,
) -> dict[str, Any]:
    service = _service(request)
    incident_id = _validate_uuid(incident_id, "incident_id")
    endpoint = "incident-timeline" if timeline else "incident-detections"
    _validate_page(limit, offset, 500 if timeline else 200, cursor)
    cursor_key = _decode_cursor(service, cursor, endpoint)
    cursor_time = None
    cursor_detection_id = None
    if cursor_key is not None:
        cursor_time = _validate_cursor_time(cursor_key.get("eventtime"), "cursor")
        cursor_detection_id = cursor_key.get("detection_id")
        if not isinstance(cursor_detection_id, str):
            raise invalid_parameter("cursor is malformed", "cursor")
        _validate_uuid(cursor_detection_id, "cursor")

    incident_path = _path(service, "incidents")
    relations_path = _path(service, "incident_detections")
    detections_path = _path(service, "detections")

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        incident = _one_or_missing(
            connection,
            "SELECT * FROM read_parquet(?) WHERE incident_id = ? LIMIT 2",
            [incident_path, incident_id],
            "incident",
        )
        total = _verify_incident_relationships(connection, service, incident_id)
        page_cursor = ""
        cursor_params: list[Any] = []
        if cursor_key is not None:
            if cursor_time is None:
                page_cursor = (
                    " AND TRY_CAST(d.eventtime AS HUGEINT) IS NULL "
                    "AND d.detection_id > ?"
                )
                cursor_params = [cursor_detection_id]
            else:
                page_cursor = (
                    " AND (TRY_CAST(d.eventtime AS HUGEINT) > CAST(? AS HUGEINT) "
                    "OR TRY_CAST(d.eventtime AS HUGEINT) IS NULL "
                    "OR (TRY_CAST(d.eventtime AS HUGEINT) = CAST(? AS HUGEINT) "
                    "AND d.detection_id > ?))"
                )
                cursor_params = [cursor_time, cursor_time, cursor_detection_id]
        select_fields = "d.*" if not timeline else (
            "d.detection_id, d.eventtime, d.date, d.time, d.tz, d.rule_id, d.rule_name, "
            "d.severity, d.srcip, d.dstip, d.username, d.host, d.source_file, d.line_number"
        )
        rows = row_dicts(
            connection.execute(
                f"""
                SELECT {select_fields}
                FROM read_parquet(?) r
                JOIN read_parquet(?) d USING (detection_id)
                WHERE r.incident_id = ?{page_cursor}
                ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST, d.detection_id ASC
                LIMIT ? OFFSET ?
                """,
                [
                    relations_path,
                    detections_path,
                    incident_id,
                    *cursor_params,
                    limit + 1,
                    offset,
                ],
            )
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            _validate_stored_timestamp(last.get("eventtime"), "eventtime")
            next_cursor = _encode_cursor(
                service,
                endpoint,
                {"eventtime": last.get("eventtime"), "detection_id": last["detection_id"]},
            )
        if timeline:
            for item in rows:
                _validate_stored_timestamp(item.get("eventtime"), "eventtime")
            items = rows
            return {
                "incident_id": incident_id,
                "items": items,
                "pagination": _pagination(limit, offset, total, next_cursor),
            }
        return {
            "incident": _decode_incident(incident),
            "detections": [_decode_detection(row) for row in rows],
            "detections_pagination": _pagination(limit, offset, total, next_cursor),
        }

    return await service.run(query)


@router.get("/incidents/{incident_id}")
async def incident_detail(
    request: Request,
    incident_id: str,
    limit: int = 50,
    offset: int = 0,
    cursor: str | None = None,
) -> dict[str, Any]:
    return await _incident_page(request, incident_id, limit, offset, cursor, timeline=False)


@router.get("/incidents/{incident_id}/timeline")
async def incident_timeline(
    request: Request,
    incident_id: str,
    limit: int = 100,
    offset: int = 0,
    cursor: str | None = None,
) -> dict[str, Any]:
    return await _incident_page(request, incident_id, limit, offset, cursor, timeline=True)


@router.get("/incidents/{incident_id}/graph")
async def incident_graph(
    request: Request,
    incident_id: str,
    depth: int = 1,
    include_derived: bool = True,
    node_type: list[str] | None = Query(default=None),
    edge_type: list[str] | None = Query(default=None),
    max_nodes: int = 1000,
) -> dict[str, Any]:
    service = _service(request)
    incident_id = _validate_uuid(incident_id, "incident_id")
    if not 1 <= depth <= 3:
        raise invalid_parameter("depth must be between 1 and 3", "depth")
    if not 1 <= max_nodes <= 5000:
        raise invalid_parameter("max_nodes must be between 1 and 5000", "max_nodes")
    if node_type and any(value not in NODE_TYPES for value in node_type):
        raise invalid_parameter("node_type contains an unsupported type", "node_type")
    if edge_type and (
        len(edge_type) > 20
        or any(not value or len(value) > 64 for value in edge_type)
    ):
        raise invalid_parameter("edge_type accepts at most 20 non-empty values of 64 characters", "edge_type")

    relations_path = _path(service, "incident_detections")
    graph_path = _path(service, "graph")

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        _one_or_missing(
            connection,
            "SELECT incident_id FROM read_parquet(?) WHERE incident_id = ? LIMIT 2",
            [_path(service, "incidents"), incident_id],
            "incident",
        )
        relation_count = _verify_incident_relationships(connection, service, incident_id)
        graph_size = service.config.graph_path.stat().st_size
        if graph_size > service.config.max_graph_file_bytes:
            raise ApiError(
                413,
                "graph_too_large",
                "The configured graph exceeds the input size limit",
                {"max_graph_file_bytes": service.config.max_graph_file_bytes},
            )

        edge_walk_filter = ""
        edge_walk_params: list[Any] = []
        if edge_type:
            edge_walk_filter = f" AND e.rel IN ({', '.join('?' for _ in edge_type)})"
            edge_walk_params.extend(edge_type)
        edge_output_filter = ""
        edge_output_params: list[Any] = []
        if edge_type:
            edge_output_filter = f" AND e.rel IN ({', '.join('?' for _ in edge_type)})"
            edge_output_params.extend(edge_type)
        node_filter = ""
        node_filter_params: list[Any] = []
        if node_type:
            node_filter = (
                f" AND (n.type IN ({', '.join('?' for _ in node_type)}) "
                "OR n.id IN (SELECT node_id FROM seeds))"
            )
            node_filter_params.extend(node_type)

        sql = f"""
            WITH RECURSIVE
            seeds(node_id) AS MATERIALIZED (
                SELECT 'inc:' || ?
                UNION
                SELECT 'det:' || detection_id
                FROM read_parquet(?) WHERE incident_id = ?
            ),
            raw_edges AS MATERIALIZED (
                SELECT
                    json_extract_string(j.value, '$.source') AS source,
                    json_extract_string(j.value, '$.target') AS target,
                    json_extract_string(j.value, '$.rel') AS rel,
                    TRY_CAST(json_extract(j.value, '$.observed') AS BOOLEAN) AS observed,
                    j.value AS payload
                FROM read_json_auto(?) g
                CROSS JOIN LATERAL json_each(to_json(g.edges)) j
            ),
            raw_nodes AS MATERIALIZED (
                SELECT
                    json_extract_string(j.value, '$.id') AS id,
                    json_extract_string(j.value, '$.type') AS type,
                    j.value AS payload
                FROM read_json_auto(?) g
                CROSS JOIN LATERAL json_each(to_json(g.nodes)) j
            ),
            walk(node_id, depth) AS (
                SELECT node_id, 0 FROM seeds
                UNION
                SELECT CASE WHEN e.source = w.node_id THEN e.target ELSE e.source END,
                       w.depth + 1
                FROM walk w
                JOIN raw_edges e ON e.source = w.node_id OR e.target = w.node_id
                WHERE w.depth < ?
                  AND (? OR e.observed)
                  {edge_walk_filter}
            ),
            selected_ids AS MATERIALIZED (
                SELECT DISTINCT node_id FROM walk
            ),
            missing_nodes AS MATERIALIZED (
                SELECT s.node_id
                FROM selected_ids s
                LEFT JOIN raw_nodes n ON n.id = s.node_id
                WHERE n.id IS NULL
            ),
            selected_nodes AS MATERIALIZED (
                SELECT n.id, n.type, n.payload
                FROM selected_ids s
                JOIN raw_nodes n ON n.id = s.node_id
                WHERE TRUE {node_filter}
            ),
            selected_edges AS MATERIALIZED (
                SELECT e.source, e.target, e.rel, e.payload
                FROM raw_edges e
                JOIN selected_nodes source_node ON source_node.id = e.source
                JOIN selected_nodes target_node ON target_node.id = e.target
                WHERE (? OR e.observed)
                  {edge_output_filter}
            ),
            stats AS (
                SELECT
                    (SELECT count(*) FROM selected_nodes) AS node_count,
                    (SELECT count(*) FROM selected_edges) AS edge_count,
                    (SELECT count(*) FROM missing_nodes) AS missing_count
            ),
            records AS (
                SELECT 'node' AS kind, n.id AS sort_a, '' AS sort_b, '' AS sort_c,
                       to_json(n.payload) AS payload
                FROM selected_nodes n
                UNION ALL
                SELECT 'edge' AS kind, e.source AS sort_a, e.target AS sort_b, e.rel AS sort_c,
                       to_json(e.payload) AS payload
                FROM selected_edges e
            )
            SELECT records.kind, records.payload, stats.node_count, stats.edge_count, stats.missing_count
            FROM records CROSS JOIN stats
            ORDER BY records.kind ASC, records.sort_a ASC, records.sort_b ASC, records.sort_c ASC
            LIMIT ?
        """
        params = [
            incident_id,
            relations_path,
            incident_id,
            graph_path,
            graph_path,
            depth,
            include_derived,
            *edge_walk_params,
            *node_filter_params,
            include_derived,
            *edge_output_params,
            max_nodes + service.config.max_graph_edges + 1,
        ]
        cursor = connection.execute(sql, params)
        node_rows: list[dict[str, Any]] = []
        edge_rows: list[dict[str, Any]] = []
        response_bytes = 0
        counts: tuple[int, int, int] | None = None
        while row := cursor.fetchone():
            kind, payload_text, node_count, edge_count, missing_count = row
            counts = (node_count, edge_count, missing_count)
            if missing_count:
                raise DataIntegrityError(
                    "A selected graph edge or seed references a missing graph node",
                    {"missing_node_count": missing_count},
                )
            if node_count > max_nodes or edge_count > service.config.max_graph_edges:
                raise ApiError(
                    413,
                    "graph_too_large",
                    "The selected graph exceeds the configured response limits",
                    {
                        "node_count": node_count,
                        "edge_count": edge_count,
                        "max_nodes": max_nodes,
                        "max_edges": service.config.max_graph_edges,
                    },
                )
            if not isinstance(payload_text, str):
                raise DataIntegrityError("A graph record could not be serialized as JSON")
            response_bytes += len(payload_text.encode("utf-8"))
            if response_bytes > service.config.max_response_bytes:
                raise ApiError(
                    413,
                    "graph_too_large",
                    "The selected graph exceeds the response byte limit",
                    {"max_response_bytes": service.config.max_response_bytes},
                )
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError as exc:
                raise DataIntegrityError("A graph record contains invalid JSON") from exc
            if not isinstance(payload, dict):
                raise DataIntegrityError("A graph record has an unexpected JSON shape")
            if kind == "node":
                node_rows.append(payload)
            elif kind == "edge":
                edge_rows.append(payload)
            else:
                raise DataIntegrityError("Graph query returned an unknown record type")

        if counts is None:
            raise DataIntegrityError("Graph query returned no seed records")
        nodes_by_id: dict[str, dict[str, Any]] = {}
        for node in node_rows:
            node_id = node.get("id")
            if (
                not isinstance(node_id, str)
                or not isinstance(node.get("type"), str)
                or not isinstance(node.get("value"), str)
            ):
                raise DataIntegrityError("A selected graph node has invalid fields")
            if node_id in nodes_by_id:
                raise DataIntegrityError("The graph contains duplicate selected node IDs")
            nodes_by_id[node_id] = {"id": node_id, "type": node["type"], "value": node["value"]}

        incident_node_id = f"inc:{incident_id}"
        expected_seeds = {incident_node_id}
        expected_seeds.update(
            f"det:{row[0]}"
            for row in connection.execute(
                "SELECT detection_id FROM read_parquet(?) WHERE incident_id = ?",
                [relations_path, incident_id],
            ).fetchall()
        )
        if not expected_seeds.issubset(nodes_by_id):
            raise DataIntegrityError(
                "The graph is missing an incident or linked-detection seed node",
                {"missing_seed_count": len(expected_seeds - nodes_by_id.keys())},
            )

        emitted_edges: list[dict[str, Any]] = []
        for edge in edge_rows:
            source = edge.get("source")
            target = edge.get("target")
            rel = edge.get("rel")
            observed = edge.get("observed")
            if (
                not isinstance(source, str)
                or not isinstance(target, str)
                or not isinstance(rel, str)
                or not isinstance(observed, bool)
            ):
                raise DataIntegrityError("A selected graph edge has invalid fields")
            if source not in nodes_by_id or target not in nodes_by_id:
                raise DataIntegrityError("A selected graph edge has a missing endpoint")
            # Keep the stored edge fields and observed flag without reclassifying provenance.
            emitted_edges.append(edge)

        graph_metadata = connection.execute(
            "SELECT directed, multigraph FROM read_json_auto(?) LIMIT 1",
            [graph_path],
        ).fetchone()
        if not graph_metadata or not isinstance(graph_metadata[0], bool) or not isinstance(graph_metadata[1], bool):
            raise DataIntegrityError("Graph metadata is missing or malformed")
        if len(expected_seeds) != relation_count + 1:
            raise DataIntegrityError("Incident relationship seed count is inconsistent")
        return {
            "directed": graph_metadata[0],
            "multigraph": graph_metadata[1],
            "graph": {
                "incident_id": incident_id,
                "depth": depth,
                "include_derived": include_derived,
            },
            "nodes": sorted(nodes_by_id.values(), key=lambda node: node["id"]),
            "edges": sorted(
                emitted_edges,
                key=lambda edge: (edge["source"], edge["target"], edge["rel"]),
            ),
        }

    return await service.run(query)


@router.get("/detections/{detection_id}")
async def detection_detail(request: Request, detection_id: str) -> dict[str, Any]:
    service = _service(request)
    detection_id = _validate_uuid(detection_id, "detection_id")
    path = _path(service, "detections")

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        return _decode_detection(
            _one_or_missing(
                connection,
                "SELECT * FROM read_parquet(?) WHERE detection_id = ? LIMIT 2",
                [path, detection_id],
                "detection",
            )
        )

    return await service.run(query)


@router.get("/techniques")
async def techniques(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    cursor: str | None = None,
) -> dict[str, Any]:
    service = _service(request)
    _validate_page(limit, offset, 200, cursor)
    cursor_key = _decode_cursor(service, cursor, "techniques")
    last_id = None
    if cursor_key is not None:
        last_id = cursor_key.get("technique_id")
        if not isinstance(last_id, str) or not last_id:
            raise invalid_parameter("cursor is malformed", "cursor")
    path = _path(service, "detections")

    def query(connection: duckdb.DuckDBPyConnection) -> dict[str, Any]:
        invalid_json = connection.execute(
            """
            SELECT count(*) FROM read_parquet(?)
            WHERE mitre_techniques IS NOT NULL AND NOT json_valid(mitre_techniques)
            """,
            [path],
        ).fetchone()[0]
        if invalid_json:
            raise DataIntegrityError(
                "Stored mitre_techniques contains invalid JSON",
                {"invalid_record_count": invalid_json},
            )
        invalid_shape = connection.execute(
            """
            SELECT count(*) FROM read_parquet(?)
            WHERE mitre_techniques IS NOT NULL
              AND json_type(CAST(mitre_techniques AS JSON)) <> 'ARRAY'
            """,
            [path],
        ).fetchone()[0]
        invalid_items = connection.execute(
            """
            SELECT count(*)
            FROM read_parquet(?) d
            CROSS JOIN LATERAL json_each(CAST(d.mitre_techniques AS JSON)) j
            WHERE d.mitre_techniques IS NOT NULL
              AND (json_type(j.value) <> 'VARCHAR' OR json_extract_string(j.value, '$') = '')
            """,
            [path],
        ).fetchone()[0]
        if invalid_shape or invalid_items:
            raise DataIntegrityError(
                "Stored mitre_techniques has an unexpected JSON shape",
                {"invalid_record_count": invalid_shape, "invalid_item_count": invalid_items},
            )

        cte = """
            WITH technique_rows AS (
                SELECT json_extract_string(j.value, '$') AS technique_id,
                       d.detection_id
                FROM read_parquet(?) d
                CROSS JOIN LATERAL json_each(CAST(d.mitre_techniques AS JSON)) j
                WHERE d.mitre_techniques IS NOT NULL
            ),
            aggregated AS (
                SELECT technique_id, count(DISTINCT detection_id) AS detection_count
                FROM technique_rows
                GROUP BY technique_id
            )
        """
        total = connection.execute(
            cte + " SELECT count(*) FROM aggregated",
            [path],
        ).fetchone()[0]
        keyset = " WHERE technique_id > ?" if last_id is not None else ""
        page_params: list[Any] = [path]
        if last_id is not None:
            page_params.append(last_id)
        page_params.extend([limit + 1, offset])
        rows = row_dicts(
            connection.execute(
                cte
                + " SELECT * FROM aggregated"
                + keyset
                + " ORDER BY technique_id ASC LIMIT ? OFFSET ?",
                page_params,
            )
        )
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = _encode_cursor(
                service,
                "techniques",
                {"technique_id": rows[-1]["technique_id"]},
            )
        return {
            "items": rows,
            "pagination": _pagination(limit, offset, total, next_cursor),
        }

    return await service.run(query)
