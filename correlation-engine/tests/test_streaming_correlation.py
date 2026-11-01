import json
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from correlate import run


class StreamingCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)
        self.input_path = self.directory / "detections.parquet"
        self.incidents_path = self.directory / "incidents.parquet"
        self.relations_path = self.directory / "relations.parquet"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_external_ordering_preserves_time_window_clusters(self):
        rows = [
            ("a", "192.0.2.1", "100", 1),
            ("b", "192.0.2.1", "150", 1),
            ("c", "192.0.2.1", "1000", 2),
            ("d", "192.0.2.2", "110", 3),
            ("e", None, "120", 4),
            ("f", None, "130", 5),
            ("g", "192.0.2.3", None, 6),
            ("h", "192.0.2.3", "10000", 7),
        ]
        schema = pa.schema([
            ("detection_id", pa.string()),
            ("rule_id", pa.string()),
            ("category", pa.string()),
            ("severity", pa.string()),
            ("srcip", pa.string()),
            ("dstip", pa.string()),
            ("username", pa.string()),
            ("host", pa.string()),
            ("eventtime", pa.string()),
            ("source_file", pa.string()),
            ("line_number", pa.int64()),
        ])
        detections = [
            {
                "detection_id": detection_id,
                "rule_id": "RULE-1",
                "category": "test",
                "severity": "medium",
                "srcip": srcip,
                "dstip": None,
                "username": None,
                "host": None,
                "eventtime": eventtime,
                "source_file": "sample.log",
                "line_number": line_number,
            }
            for detection_id, srcip, eventtime, line_number in rows
        ]
        pq.write_table(
            pa.Table.from_pylist(detections, schema=schema),
            self.input_path,
        )

        run(
            str(self.input_path),
            str(self.incidents_path),
            str(self.relations_path),
            window=100,
            memory_limit="128MB",
            temp_directory=self.directory / "duckdb-temp",
        )

        incidents = pq.read_table(self.incidents_path).to_pylist()
        relations = pq.read_table(self.relations_path).to_pylist()
        detection_groups = {}
        for relation in relations:
            detection_groups.setdefault(relation["incident_id"], set()).add(
                relation["detection_id"]
            )
        actual_groups = {frozenset(group) for group in detection_groups.values()}
        expected_groups = {
            frozenset({"a", "b"}),
            frozenset({"c"}),
            frozenset({"d"}),
            frozenset({"e"}),
            frozenset({"f"}),
            frozenset({"g", "h"}),
        }

        self.assertEqual(len(incidents), 6)
        self.assertEqual(len(relations), len(rows))
        self.assertEqual(actual_groups, expected_groups)
        self.assertTrue(all(row["confidence"] is None for row in incidents))
        self.assertTrue(all(
            row["title"].startswith("Observation cluster:") for row in incidents
        ))
        self.assertTrue(all(
            "not a confirmed incident" in row["description"] for row in incidents
        ))
        correlated = next(row for row in incidents if row["detection_count"] == 2 and
                          "a" in json.loads(row["detection_ids"]))
        self.assertEqual(correlated["unique_source_events"], 1)
        self.assertEqual(json.loads(correlated["related_srcips"]), ["192.0.2.1"])

    def test_equal_time_attack_path_order_uses_source_evidence_not_detection_ids(self):
        detections = [
            ("z-last", "RULE-Z", "z.log", 2, "192.0.2.1", "100"),
            ("b-second", "RULE-B", "a.log", 20, "192.0.2.1", "100"),
            ("a-first", "RULE-A", "a.log", 10, "192.0.2.1", "100"),
            ("next", "RULE-A", "a.log", 30, "192.0.2.1", "150"),
        ]
        schema = pa.schema([
            ("detection_id", pa.string()),
            ("rule_id", pa.string()),
            ("category", pa.string()),
            ("severity", pa.string()),
            ("srcip", pa.string()),
            ("dstip", pa.string()),
            ("username", pa.string()),
            ("host", pa.string()),
            ("eventtime", pa.string()),
            ("source_file", pa.string()),
            ("line_number", pa.int64()),
        ])
        rows = [
            {
                "detection_id": detection_id,
                "rule_id": rule_id,
                "category": "test",
                "severity": "medium",
                "srcip": srcip,
                "dstip": None,
                "username": None,
                "host": None,
                "eventtime": eventtime,
                "source_file": source_file,
                "line_number": line_number,
            }
            for detection_id, rule_id, source_file, line_number, srcip, eventtime
            in detections
        ]
        pq.write_table(pa.Table.from_pylist(rows, schema=schema), self.input_path)
        second_incidents = self.directory / "incidents-second.parquet"
        second_relations = self.directory / "relations-second.parquet"

        for incident_path, relation_path in (
            (self.incidents_path, self.relations_path),
            (second_incidents, second_relations),
        ):
            run(
                str(self.input_path),
                str(incident_path),
                str(relation_path),
                window=100,
                memory_limit="128MB",
                temp_directory=self.directory / "duckdb-temp",
            )

        first = pq.read_table(self.incidents_path).to_pylist()[0]
        second = pq.read_table(second_incidents).to_pylist()[0]
        expected_ids = ["a-first", "b-second", "z-last", "next"]
        expected_refs = [
            {"source_file": "a.log", "line_number": 10},
            {"source_file": "a.log", "line_number": 20},
            {"source_file": "z.log", "line_number": 2},
            {"source_file": "a.log", "line_number": 30},
        ]
        self.assertEqual(json.loads(first["detection_ids"]), expected_ids)
        self.assertEqual(json.loads(second["detection_ids"]), expected_ids)
        self.assertEqual(json.loads(first["evidence_refs"]), expected_refs)
        self.assertEqual(json.loads(second["evidence_refs"]), expected_refs)


if __name__ == "__main__":
    unittest.main()
