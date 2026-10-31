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
        correlated = next(row for row in incidents if row["detection_count"] == 2 and
                          "a" in json.loads(row["detection_ids"]))
        self.assertEqual(correlated["unique_source_events"], 1)
        self.assertEqual(json.loads(correlated["related_srcips"]), ["192.0.2.1"])


if __name__ == "__main__":
    unittest.main()
