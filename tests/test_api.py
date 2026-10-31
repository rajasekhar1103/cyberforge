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


SAMPLE_DIR = Path(os.environ.get("CYBERFORGE_TEST_DATA_DIR", Path(tempfile.gettempdir()) / "kilo"))
CONTRACT_PATH = Path(__file__).resolve().parents[1] / "docs" / "api-data-contracts.md"
DETECTIONS_PATH = SAMPLE_DIR / "detections.parquet"
INCIDENTS_PATH = SAMPLE_DIR / "incidents.parquet"
RELATIONS_PATH = SAMPLE_DIR / "incident_detections.parquet"
GRAPH_PATH = SAMPLE_DIR / "graph.json"


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
        missing = [path for path in (DETECTIONS_PATH, INCIDENTS_PATH, RELATIONS_PATH, GRAPH_PATH) if not path.is_file()]
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
            [str(RELATIONS_PATH), str(RELATIONS_PATH)],
        ).fetchone()
        cls.contract_schema = _read_contract_schema()
        cls.config = ApiConfig(
            detections_path=DETECTIONS_PATH,
            incidents_path=INCIDENTS_PATH,
            incident_detections_path=RELATIONS_PATH,
            graph_path=GRAPH_PATH,
            duckdb_memory_limit="128MB",
            duckdb_temp_directory=Path(tempfile.gettempdir()) / "cyberforge-api-test-temp",
        )
        cls.client = TestClient(create_app(cls.config))
        cls.client.__enter__()
        connection.close()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.__exit__(None, None, None)

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
                [str(DETECTIONS_PATH), self.detection_id],
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
        absent = "00000000-0000-4000-8000-000000000001"
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
                [str(RELATIONS_PATH)],
            ).fetchone()[0]
            expected = connection.execute(
                """
                SELECT d.detection_id, d.eventtime
                FROM read_parquet(?) r
                JOIN read_parquet(?) d USING (detection_id)
                WHERE r.incident_id = ?
                ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST, d.detection_id ASC
                """,
                [str(RELATIONS_PATH), str(DETECTIONS_PATH), incident_id],
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
                detections_path=DETECTIONS_PATH,
                incidents_path=temp / "missing.parquet",
                incident_detections_path=RELATIONS_PATH,
                graph_path=GRAPH_PATH,
                duckdb_temp_directory=temp / "duckdb-temp",
            )
            with TestClient(create_app(missing_config)) as client:
                response = client.get("/api/health")
                self.assert_error(response, 503, "service_unavailable")
                self.assertIn("incidents", response.json()["error"]["details"]["stores"])

            unreadable = temp / "unreadable.parquet"
            unreadable.write_text("not a parquet file", encoding="utf-8")
            unreadable_config = ApiConfig(
                detections_path=DETECTIONS_PATH,
                incidents_path=unreadable,
                incident_detections_path=RELATIONS_PATH,
                graph_path=GRAPH_PATH,
                duckdb_temp_directory=temp / "duckdb-temp-2",
            )
            with TestClient(create_app(unreadable_config)) as client:
                self.assert_error(client.get("/api/health"), 503, "service_unavailable")

            missing_graph_config = ApiConfig(
                detections_path=DETECTIONS_PATH,
                incidents_path=INCIDENTS_PATH,
                incident_detections_path=RELATIONS_PATH,
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
                        SELECT ?, '00000000-0000-4000-8000-000000000099'
                    ) TO ? (FORMAT PARQUET)
                    """,
                    [str(RELATIONS_PATH), self.incident_id, str(relation_copy)],
                )
            broken_config = ApiConfig(
                detections_path=DETECTIONS_PATH,
                incidents_path=INCIDENTS_PATH,
                incident_detections_path=relation_copy,
                graph_path=GRAPH_PATH,
                duckdb_temp_directory=Path(temporary) / "duckdb-temp",
            )
            with TestClient(create_app(broken_config)) as client:
                response = client.get(f"/api/incidents/{self.incident_id}")
                self.assert_error(response, 503, "data_integrity_error")

    def test_graph_dangling_endpoint_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            graph_copy = Path(temporary) / "dangling-graph.json"
            graph = json.loads(GRAPH_PATH.read_text(encoding="utf-8"))
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
                detections_path=DETECTIONS_PATH,
                incidents_path=INCIDENTS_PATH,
                incident_detections_path=RELATIONS_PATH,
                graph_path=graph_copy,
                duckdb_temp_directory=Path(temporary) / "duckdb-temp",
            )
            with TestClient(create_app(broken_graph_config)) as client:
                response = client.get(f"/api/incidents/{self.incident_id}/graph")
                self.assert_error(response, 503, "data_integrity_error")


if __name__ == "__main__":
    unittest.main()
