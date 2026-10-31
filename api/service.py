from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import json
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import duckdb

from api.config import ApiConfig
from api.errors import ApiError, DataIntegrityError

logger = logging.getLogger("cyberforge.api")
T = TypeVar("T")

PARQUET_COLUMNS = {
    "detections": {
        "detection_id", "rule_id", "rule_name", "category", "severity", "description",
        "srcip", "dstip", "username", "host", "eventtime", "date", "time", "tz",
        "source_file", "line_number", "evidence", "matched_conditions", "confidence",
        "mitre_techniques",
    },
    "incidents": {
        "incident_id", "title", "description", "severity", "confidence", "first_observed",
        "last_observed", "detection_count", "unique_source_events", "related_srcips",
        "related_dstips", "related_usernames", "related_hosts", "detection_ids",
        "correlation_reasons", "evidence_refs", "status",
    },
    "incident_detections": {"incident_id", "detection_id"},
}

STORE_PATHS = {
    "detections": "detections_path",
    "incidents": "incidents_path",
    "incident_detections": "incident_detections_path",
    "graph": "graph_path",
}


class AnalyticsService:
    def __init__(self, config: ApiConfig) -> None:
        self.config = config
        self._query_slots = asyncio.Semaphore(config.max_concurrent_queries)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="cyberforge-duckdb",
        )
        self._connection: duckdb.DuckDBPyConnection | None = None
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        if self._connection is not None:
            self._executor.submit(self._connection.close).result()
            self._connection = None
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._closed = True

    def dataset_generation(self) -> str:
        digest = hashlib.sha256()
        for store_name, attribute in STORE_PATHS.items():
            path = getattr(self.config, attribute)
            try:
                stat = path.stat()
            except OSError as exc:
                raise ApiError(
                    503,
                    "service_unavailable",
                    "A required analytics store is unavailable",
                    {"store": store_name},
                ) from exc
            digest.update(f"{store_name}:{path}:{stat.st_size}:{stat.st_mtime_ns}\n".encode("utf-8"))
        return digest.hexdigest()

    async def run(self, operation: Callable[[duckdb.DuckDBPyConnection], T]) -> T:
        if self._query_slots.locked():
            raise ApiError(503, "service_unavailable", "The analytics query limit is currently full")
        await self._query_slots.acquire()

        loop = asyncio.get_running_loop()
        cancellation_requested = threading.Event()
        state_lock = threading.Lock()
        state: dict[str, Any] = {}

        def execute() -> T:
            if self._closed:
                raise RuntimeError("The analytics service is shut down")
            if self._connection is None:
                self.config.duckdb_temp_directory.mkdir(parents=True, exist_ok=True)
                connection = duckdb.connect(database=":memory:")
                try:
                    connection.execute("SET memory_limit = ?", [self.config.duckdb_memory_limit])
                    connection.execute("SET threads = ?", [self.config.duckdb_threads])
                    connection.execute("SET temp_directory = ?", [str(self.config.duckdb_temp_directory)])
                except duckdb.Error:
                    connection.close()
                    raise
                self._connection = connection
            with state_lock:
                connection = self._connection
                state["connection"] = connection
                already_cancelled = cancellation_requested.is_set()
            if already_cancelled:
                raise duckdb.InterruptException("Query deadline expired before execution")
            if connection is None:
                raise RuntimeError("DuckDB connection initialization failed")
            return operation(connection)

        future = asyncio.wrap_future(self._executor.submit(execute), loop=loop)
        future.add_done_callback(lambda _: self._query_slots.release())
        future.add_done_callback(
            lambda completed: completed.exception() if not completed.cancelled() else None
        )

        try:
            return await asyncio.wait_for(
                asyncio.shield(future),
                timeout=self.config.query_timeout_seconds,
            )
        except TimeoutError as exc:
            with state_lock:
                cancellation_requested.set()
                connection = state.get("connection")
                if connection is not None:
                    try:
                        connection.interrupt()
                    except duckdb.Error:
                        logger.debug("DuckDB query had already completed during timeout cancellation")
            logger.warning("DuckDB query deadline expired")
            raise ApiError(504, "query_timeout", "The analytics query exceeded its deadline") from exc
        except (duckdb.IOException, duckdb.PermissionException, duckdb.InvalidInputException) as exc:
            logger.error("DuckDB could not read a configured analytics store: %s", exc)
            raise ApiError(503, "service_unavailable", "A configured analytics store is unavailable") from exc
        except duckdb.Error as exc:
            logger.exception("DuckDB query failed")
            raise ApiError(500, "internal_error", "The analytics query failed") from exc
        except OSError as exc:
            logger.error("DuckDB temporary storage is unavailable: %s", exc)
            raise ApiError(503, "service_unavailable", "Analytics temporary storage is unavailable") from exc

    async def check_stores(self) -> None:
        def check(connection: duckdb.DuckDBPyConnection) -> None:
            unavailable: list[str] = []
            for name, attribute in STORE_PATHS.items():
                path: Path = getattr(self.config, attribute)
                try:
                    if not path.is_file() or path.stat().st_size == 0:
                        unavailable.append(name)
                        continue
                    if name == "graph":
                        if path.stat().st_size > self.config.max_graph_file_bytes:
                            unavailable.append(name)
                            continue
                        rows = connection.execute(
                            """
                            SELECT directed, multigraph,
                                   json_type(to_json(nodes)), json_type(to_json(edges))
                            FROM read_json_auto(?) LIMIT 1
                            """,
                            [str(path)],
                        ).fetchall()
                        if not rows or rows[0][0] is None or rows[0][1] is None:
                            unavailable.append(name)
                        elif rows[0][2] != "ARRAY" or rows[0][3] != "ARRAY":
                            unavailable.append(name)
                        continue

                    columns = {
                        row[0]
                        for row in connection.execute(
                            "DESCRIBE SELECT * FROM read_parquet(?)",
                            [str(path)],
                        ).fetchall()
                    }
                    if not PARQUET_COLUMNS[name].issubset(columns):
                        unavailable.append(name)
                except (duckdb.Error, OSError):
                    unavailable.append(name)
            if unavailable:
                logger.error("Required analytics stores are unavailable: %s", unavailable)
                raise ApiError(
                    503,
                    "service_unavailable",
                    "One or more required analytics stores are unavailable",
                    {"stores": unavailable},
                )

        await self.run(check)


def decode_json_field(
    row: dict[str, Any],
    field: str,
    expected_type: type | tuple[type, ...],
    *,
    required: bool = False,
) -> None:
    value = row.get(field)
    if value is None:
        if required:
            raise DataIntegrityError(
                f"Stored field {field} is null",
                {"field": field},
            )
        return
    if not isinstance(value, str):
        raise DataIntegrityError(
            f"Stored field {field} is not JSON text",
            {"field": field},
        )
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.error("Invalid JSON text in analytics field %s", field)
        raise DataIntegrityError(
            f"Stored field {field} contains invalid JSON",
            {"field": field},
        ) from exc
    if decoded is None:
        row[field] = None
        return
    if not isinstance(decoded, expected_type):
        raise DataIntegrityError(
            f"Stored field {field} has an unexpected JSON shape",
            {"field": field},
        )
    row[field] = decoded


def row_dicts(cursor: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]
