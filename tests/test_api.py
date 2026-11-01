from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

import duckdb
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from api.app import create_app
from api.config import ApiConfig


CONTRACT_PATH = Path(__file__).resolve().parents[1] / "docs" / "api-data-contracts.md"


def _sample_id(index: int) -> str:
    return f"00000000-0000-4000-8000-{index:012d}"


def _write_sample_artifacts(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    detections = []
    incident_detection_ids: dict[int, list[str]] = {}
    for index in range(1, 183):
        incident_index = 1 if index <= 2 else index - 1
        detection_id = _sample_id(index)
        incident_detection_ids.setdefault(incident_index, []).append(detection_id)
        detections.append((
            detection_id,
            "RULE-001",
            "Sample detection",
            "authentication",
            "medium",
            "Synthetic API test evidence",
            "192.0.2.10",
            "198.51.100.20",
            "analyst",
            "firewall-01",
            str(1_700_000_000_000_000_000 + index * 100),
            "2023-11-14",
            "22:13:20",
            "UTC",
            "sample.log",
            index,
            json.dumps({"srcip": "192.0.2.10", "user": "analyst"}),
            "[]",
            None,
            '["T1110"]',
        ))

    incidents = []
    relationships = []
    for index, detection_ids in incident_detection_ids.items():
        incident_id = _sample_id(index)
        detection_indices = [int(detection_id[-12:]) for detection_id in detection_ids]
        first_eventtime = str(
            1_700_000_000_000_000_000 + min(detection_indices) * 100
        )
        last_eventtime = str(
            1_700_000_000_000_000_000 + max(detection_indices) * 100
        )
        incidents.append((
            incident_id,
            "Observation cluster: authentication",
            "Synthetic cluster for API tests; not a confirmed incident",
            "medium",
            None,
            first_eventtime,
            last_eventtime,
            len(detection_ids),
            len(detection_ids),
            '["192.0.2.10"]',
            '["198.51.100.20"]',
            '["analyst"]',
            '["firewall-01"]',
            json.dumps(detection_ids),
            '["shared source IP"]' if len(detection_ids) > 1 else '["single detection"]',
            json.dumps([
                {"source_file": "sample.log", "line_number": detection_index}
                for detection_index in detection_indices
            ]),
            "open",
        ))
        relationships.extend((incident_id, detection_id) for detection_id in detection_ids)

    graph_nodes: dict[str, dict[str, str]] = {}
    graph_edges = []
    for index, detection in enumerate(detections, start=1):
        detection_id = detection[0]
        incident_id = _sample_id(1 if index <= 2 else index - 1)
        nodes = (
            (f"det:{detection_id}", "detection", detection_id),
            ("ip:192.0.2.10", "ip", "192.0.2.10"),
            ("ip:198.51.100.20", "ip", "198.51.100.20"),
            ("user:analyst", "user", "analyst"),
            ("host:firewall-01", "host", "firewall-01"),
            ("tech:T1110", "technique", "T1110"),
            (f"inc:{incident_id}", "incident", incident_id),
        )
        graph_nodes.update({
            node_id: {"id": node_id, "type": node_type, "value": value}
            for node_id, node_type, value in nodes
        })
        graph_edges.extend([
            {
                "source": "ip:192.0.2.10",
                "target": f"det:{detection_id}",
                "rel": "OBSERVED_SOURCE",
                "evidence": "sample.log",
                "line": index,
                "observed": True,
            },
            {
                "source": f"det:{detection_id}",
                "target": "ip:198.51.100.20",
                "rel": "OBSERVED_DESTINATION",
                "evidence": "sample.log",
                "line": index,
                "observed": True,
            },
            {
                "source": f"det:{detection_id}",
                "target": "user:analyst",
                "rel": "ASSOCIATED_WITH_USER",
                "evidence": "sample.log",
                "line": index,
                "observed": True,
            },
            {
                "source": f"det:{detection_id}",
                "target": "host:firewall-01",
                "rel": "OBSERVED_ON_HOST",
                "evidence": "sample.log",
                "line": index,
                "observed": True,
            },
            {
                "source": f"det:{detection_id}",
                "target": "tech:T1110",
                "rel": "MAPPED_TO_TECHNIQUE",
                "evidence": "sample.log",
                "line": index,
                "observed": False,
            },
            {
                "source": f"det:{detection_id}",
                "target": f"inc:{incident_id}",
                "rel": "RELATED_TO_INCIDENT",
                "evidence": f"detection_id={detection_id};incident_id={incident_id}",
                "line": None,
                "observed": False,
            },
        ])

    with duckdb.connect() as connection:
        connection.execute("""
            CREATE TABLE detections (
                detection_id VARCHAR, rule_id VARCHAR, rule_name VARCHAR,
                category VARCHAR, severity VARCHAR, description VARCHAR,
                srcip VARCHAR, dstip VARCHAR, username VARCHAR, host VARCHAR,
                eventtime VARCHAR, date VARCHAR, time VARCHAR, tz VARCHAR,
                source_file VARCHAR, line_number BIGINT, evidence VARCHAR,
                matched_conditions VARCHAR, confidence VARCHAR,
                mitre_techniques VARCHAR
            )
        """)
        connection.executemany(
            "INSERT INTO detections VALUES (" + ",".join(["?"] * 20) + ")",
            detections,
        )
        connection.execute("""
            CREATE TABLE incidents (
                incident_id VARCHAR, title VARCHAR, description VARCHAR,
                severity VARCHAR, confidence VARCHAR, first_observed VARCHAR,
                last_observed VARCHAR, detection_count BIGINT,
                unique_source_events BIGINT, related_srcips VARCHAR,
                related_dstips VARCHAR, related_usernames VARCHAR,
                related_hosts VARCHAR, detection_ids VARCHAR,
                correlation_reasons VARCHAR, evidence_refs VARCHAR, status VARCHAR
            )
        """)
        connection.executemany(
            "INSERT INTO incidents VALUES (" + ",".join(["?"] * 17) + ")",
            incidents,
        )
        connection.execute("""
            CREATE TABLE incident_detections (
                incident_id VARCHAR, detection_id VARCHAR
            )
        """)
        connection.executemany(
            "INSERT INTO incident_detections VALUES (?, ?)",
            relationships,
        )
        for table, filename in (
            ("detections", "detections.parquet"),
            ("incidents", "incidents.parquet"),
            ("incident_detections", "incident_detections.parquet"),
        ):
            path = str(directory / filename).replace("'", "''")
            connection.execute(f"COPY {table} TO '{path}' (FORMAT PARQUET)")

    (directory / "graph.json").write_text(
        json.dumps({
            "directed": True,
            "multigraph": False,
            "graph": {},
            "nodes": list(graph_nodes.values()),
            "edges": graph_edges,
        }),
        encoding="utf-8",
    )


def _read_contract_schema() -> dict[str, Any]:
    text = CONTRACT_PATH.read_text(encoding="utf-8")
    title_at = text.index('"title": "CyberForge API response contracts"')
    start = text.rfind("```json", 0, title_at)
    end = text.index("```", title_at)
    schema = json.loads(text[start + len("```json") : end])
    Draft202012Validator.check_schema(schema)
    return schema


class InvestigationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        configured_directory = os.environ.get("CYBERFORGE_TEST_DATA_DIR")
        cls._temporary_data = None
        if configured_directory:
            cls.sample_dir = Path(configured_directory)
        else:
            cls._temporary_data = tempfile.TemporaryDirectory(prefix="cyberforge-api-test-")
            cls.sample_dir = Path(cls._temporary_data.name)
            _write_sample_artifacts(cls.sample_dir)

        cls.detections_path = cls.sample_dir / "detections.parquet"
        cls.incidents_path = cls.sample_dir / "incidents.parquet"
        cls.relations_path = cls.sample_dir / "incident_detections.parquet"
        cls.graph_path = cls.sample_dir / "graph.json"
        missing = [
            path for path in (
                cls.detections_path,
                cls.incidents_path,
                cls.relations_path,
                cls.graph_path,
            )
            if not path.is_file()
        ]
        if missing:
            raise RuntimeError(f"Functional sample artifacts are unavailable: {missing}")
        connection = duckdb.connect()
        cls.incident_id, cls.detection_id = connection.execute(
            """
            SELECT r.incident_id, r.detection_id
            FROM read_parquet(?) r
            JOIN (
                SELECT incident_id
                FROM read_parquet(?)
                GROUP BY incident_id
                HAVING count(*) = 1
                ORDER BY incident_id
                LIMIT 1
            ) singleton USING (incident_id)
            ORDER BY r.incident_id
            LIMIT 1
            """,
            [str(cls.relations_path), str(cls.relations_path)],
        ).fetchone()
        cls.contract_schema = _read_contract_schema()
        cls.config = ApiConfig(
            detections_path=cls.detections_path,
            incidents_path=cls.incidents_path,
            incident_detections_path=cls.relations_path,
            graph_path=cls.graph_path,
            duckdb_memory_limit="128MB",
            duckdb_temp_directory=Path(tempfile.gettempdir()) / "cyberforge-api-test-temp",
        )
        cls.client = TestClient(create_app(cls.config))
        cls.client.__enter__()
        connection.close()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)
        if cls._temporary_data is not None:
            cls._temporary_data.cleanup()

    def assert_contract(self, response: Any, definition: str) -> None:
        self.assertEqual(response.status_code, 200, response.text)
        contract = {
            "$schema": self.contract_schema["$schema"],
            "$defs": self.contract_schema["$defs"],
            "$ref": f"#/$defs/{definition}",
        }
        Draft202012Validator(contract).validate(response.json())

    def assert_error(self, response: Any, status: int, code: str) -> None:
        self.assertEqual(response.status_code, status, response.text)
        body = response.json()
        self.assertEqual(body["error"]["code"], code)
        self.assertTrue(body["error"]["request_id"])
        self.assertIn("X-Request-ID", response.headers)
        contract = {
            "$schema": self.contract_schema["$schema"],
            "$defs": self.contract_schema["$defs"],
            "$ref": "#/$defs/ErrorResponse",
        }
        Draft202012Validator(contract).validate(body)

    def test_all_successful_endpoint_contracts(self) -> None:
        cases = [
            ("/api/health", "HealthResponse"),
            ("/api/summary", "SummaryResponse"),
            ("/api/incidents?limit=2", "IncidentListResponse"),
            (f"/api/incidents/{self.incident_id}", "IncidentDetailResponse"),
            (f"/api/incidents/{self.incident_id}/timeline", "TimelineResponse"),
            (f"/api/incidents/{self.incident_id}/graph", "AttackGraphResponse"),
            (f"/api/detections/{self.detection_id}", "Detection"),
            ("/api/techniques", "TechniqueListResponse"),
        ]
        for path, definition in cases:
            with self.subTest(path=path):
                self.assert_contract(self.client.get(path), definition)

    def test_incident_filters_and_cursor_pagination(self) -> None:
        first = self.client.get("/api/incidents", params={"limit": 1})
        self.assert_contract(first, "IncidentListResponse")
        page = first.json()
        self.assertEqual(page["pagination"]["total"], 181)
        self.assertIsNotNone(page["pagination"]["next_cursor"])
        second = self.client.get(
            "/api/incidents",
            params={"limit": 1, "cursor": page["pagination"]["next_cursor"]},
        )
        self.assert_contract(second, "IncidentListResponse")
        self.assertNotEqual(page["items"][0]["incident_id"], second.json()["items"][0]["incident_id"])

        with duckdb.connect() as connection:
            detection = connection.execute(
                "SELECT srcip, username, severity FROM read_parquet(?) WHERE detection_id = ?",
                [str(self.detections_path), self.detection_id],
            ).fetchone()
        filtered = self.client.get(
            "/api/incidents",
            params={"srcip": detection[0], "username": detection[1], "severity": detection[2]},
        )
        self.assert_contract(filtered, "IncidentListResponse")
        self.assertGreaterEqual(filtered.json()["pagination"]["total"], 1)

    def test_invalid_filters_time_range_and_pagination(self) -> None:
        invalid_requests = [
            ("/api/incidents", {"severity": "urgent"}),
            ("/api/incidents", {"srcip": "not-an-ip"}),
            ("/api/incidents", {"username": ""}),
            ("/api/incidents", {"start_time": "1e10"}),
            ("/api/incidents", {"start_time": "170141183460469231731687303715884105728"}),
            ("/api/incidents", {"start_time": "200", "end_time": "100"}),
            ("/api/incidents", {"limit": 0}),
            ("/api/incidents", {"offset": 10001}),
            ("/api/incidents", {"cursor": "not-base64"}),
            ("/api/incidents", {"cursor": "abc", "offset": 1}),
            (f"/api/incidents/{self.incident_id}/timeline", {"limit": 501}),
            (f"/api/incidents/{self.incident_id}/graph", {"depth": 0}),
            (f"/api/incidents/{self.incident_id}/graph", {"max_nodes": 5001}),
            (f"/api/incidents/{self.incident_id}/graph", {"node_type": "bogus"}),
            (f"/api/incidents/{self.incident_id}/graph", {"include_derived": "sometimes"}),
        ]
        for path, params in invalid_requests:
            with self.subTest(path=path, params=params):
                self.assert_error(self.client.get(path, params=params), 400, "invalid_parameter")

    def test_missing_and_invalid_incident_and_detection_ids(self) -> None:
        self.assert_error(self.client.get("/api/incidents/not-a-uuid"), 400, "invalid_parameter")
        self.assert_error(
            self.client.get("/api/detections/not-a-uuid"),
            400,
            "invalid_parameter",
        )
        absent = _sample_id(999_999)
        self.assert_error(self.client.get(f"/api/incidents/{absent}"), 404, "not_found")
        self.assert_error(self.client.get(f"/api/detections/{absent}"), 404, "not_found")

    def test_timestamp_order_is_exact_and_strings_are_preserved(self) -> None:
        with duckdb.connect() as connection:
            incident_id = connection.execute(
                """
                SELECT incident_id FROM read_parquet(?)
                GROUP BY incident_id HAVING count(*) > 1
                ORDER BY incident_id LIMIT 1
                """,
                [str(self.relations_path)],
            ).fetchone()[0]
            expected = connection.execute(
                """
                SELECT d.detection_id, d.eventtime
                FROM read_parquet(?) r
                JOIN read_parquet(?) d USING (detection_id)
                WHERE r.incident_id = ?
                ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST, d.detection_id ASC
                """,
                [str(self.relations_path), str(self.detections_path), incident_id],
            ).fetchall()
        response = self.client.get(f"/api/incidents/{incident_id}/timeline")
        self.assert_contract(response, "TimelineResponse")
        actual = [(row["detection_id"], row["eventtime"]) for row in response.json()["items"]]
        self.assertEqual(actual, expected)
        self.assertEqual([int(row[1]) for row in actual], sorted(int(row[1]) for row in actual))

    def test_graph_depth_filters_derived_edges_and_node_limit(self) -> None:
        base = self.client.get(f"/api/incidents/{self.incident_id}/graph", params={"depth": 1})
        self.assert_contract(base, "AttackGraphResponse")
        depth_two = self.client.get(f"/api/incidents/{self.incident_id}/graph", params={"depth": 2})
        self.assert_contract(depth_two, "AttackGraphResponse")
        self.assertGreaterEqual(
            len(depth_two.json()["nodes"]),
            len(base.json()["nodes"]),
        )

        no_derived = self.client.get(
            f"/api/incidents/{self.incident_id}/graph",
            params={"include_derived": "false"},
        )
        self.assert_contract(no_derived, "AttackGraphResponse")
        self.assertTrue(all(edge["observed"] for edge in no_derived.json()["edges"]))

        ip_only = self.client.get(
            f"/api/incidents/{self.incident_id}/graph",
            params=[("node_type", "ip")],
        )
        self.assert_contract(ip_only, "AttackGraphResponse")
        self.assertTrue(
            all(
                node["type"] == "ip" or node["id"].startswith(("inc:", "det:"))
                for node in ip_only.json()["nodes"]
            )
        )

        edge_only = self.client.get(
            f"/api/incidents/{self.incident_id}/graph",
            params=[("edge_type", "OBSERVED_SOURCE")],
        )
        self.assert_contract(edge_only, "AttackGraphResponse")
        self.assertTrue(all(edge["rel"] == "OBSERVED_SOURCE" for edge in edge_only.json()["edges"]))
        self.assert_error(
            self.client.get(
                f"/api/incidents/{self.incident_id}/graph",
                params={"max_nodes": 1},
            ),
            413,
            "graph_too_large",
        )

    def test_health_reports_missing_and_unreadable_stores(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temp = Path(temporary)
            missing_config = ApiConfig(
                detections_path=self.detections_path,
                incidents_path=temp / "missing.parquet",
                incident_detections_path=self.relations_path,
                graph_path=self.graph_path,
                duckdb_temp_directory=temp / "duckdb-temp",
            )
            with TestClient(create_app(missing_config)) as client:
                response = client.get("/api/health")
                self.assert_error(response, 503, "service_unavailable")
                self.assertIn("incidents", response.json()["error"]["details"]["stores"])

            unreadable = temp / "unreadable.parquet"
            unreadable.write_text("not a parquet file", encoding="utf-8")
            unreadable_config = ApiConfig(
                detections_path=self.detections_path,
                incidents_path=unreadable,
                incident_detections_path=self.relations_path,
                graph_path=self.graph_path,
                duckdb_temp_directory=temp / "duckdb-temp-2",
            )
            with TestClient(create_app(unreadable_config)) as client:
                self.assert_error(client.get("/api/health"), 503, "service_unavailable")

            missing_graph_config = ApiConfig(
                detections_path=self.detections_path,
                incidents_path=self.incidents_path,
                incident_detections_path=self.relations_path,
                graph_path=temp / "missing-graph.json",
                duckdb_temp_directory=temp / "duckdb-temp-3",
            )
            with TestClient(create_app(missing_graph_config)) as client:
                response = client.get("/api/health")
                self.assert_error(response, 503, "service_unavailable")
                self.assertIn("graph", response.json()["error"]["details"]["stores"])

    def test_json_response_byte_limit_is_enforced(self) -> None:
        bounded_config = replace(self.config, max_response_bytes=100)
        with TestClient(create_app(bounded_config)) as client:
            self.assert_error(client.get("/api/summary"), 413, "response_too_large")

    def test_broken_incident_detection_relationship_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            relation_copy = Path(temporary) / "broken-relations.parquet"
            with duckdb.connect() as connection:
                connection.execute(
                    """
                    COPY (
                        SELECT incident_id, detection_id FROM read_parquet(?)
                        UNION ALL
                        SELECT ?, ?
                    ) TO ? (FORMAT PARQUET)
                    """,
                    [
                        str(self.relations_path),
                        self.incident_id,
                        _sample_id(999_999),
                        str(relation_copy),
                    ],
                )
            broken_config = ApiConfig(
                detections_path=self.detections_path,
                incidents_path=self.incidents_path,
                incident_detections_path=relation_copy,
                graph_path=self.graph_path,
                duckdb_temp_directory=Path(temporary) / "duckdb-temp",
            )
            with TestClient(create_app(broken_config)) as client:
                response = client.get(f"/api/incidents/{self.incident_id}")
                self.assert_error(response, 503, "data_integrity_error")

    def test_graph_dangling_endpoint_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            graph_copy = Path(temporary) / "dangling-graph.json"
            graph = json.loads(self.graph_path.read_text(encoding="utf-8"))
            detection_node = f"det:{self.detection_id}"
            matching_edge = next(
                edge
                for edge in graph["edges"]
                if edge["source"] == detection_node or edge["target"] == detection_node
            )
            if matching_edge["source"] == detection_node:
                matching_edge["target"] = "missing:node"
            else:
                matching_edge["source"] = "missing:node"
            graph_copy.write_text(json.dumps(graph), encoding="utf-8")
            broken_graph_config = ApiConfig(
                detections_path=self.detections_path,
                incidents_path=self.incidents_path,
                incident_detections_path=self.relations_path,
                graph_path=graph_copy,
                duckdb_temp_directory=Path(temporary) / "duckdb-temp",
            )
            with TestClient(create_app(broken_graph_config)) as client:
                response = client.get(f"/api/incidents/{self.incident_id}/graph")
                self.assert_error(response, 503, "data_integrity_error")


if __name__ == "__main__":
    unittest.main()
