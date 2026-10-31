import json
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from engine import run


class StreamingDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp_dir.name)
        self.input_path = self.directory / "events.parquet"
        self.rules_path = self.directory / "rules.yaml"
        self.output_path = self.directory / "detections.parquet"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_events(self, rows):
        schema = pa.schema([
            ("type", pa.string()),
            ("subtype", pa.string()),
            ("fields_json", pa.string()),
            ("source_file", pa.string()),
            ("line_number", pa.int64()),
        ])
        pq.write_table(pa.Table.from_pylist(rows, schema=schema), self.input_path)

    def write_rules(self, rules):
        self.rules_path.write_text(
            yaml.safe_dump({"rules": rules}),
            encoding="utf-8",
        )

    def test_routes_rules_by_event_type_and_preserves_detection_content(self):
        self.write_events([
            {
                "type": "event",
                "subtype": "system",
                "fields_json": json.dumps({
                    "type": "event",
                    "subtype": "system",
                    "action": "login",
                    "status": "failed",
                    "srcip": "192.0.2.10",
                    "eventtime": "1700000000",
                }),
                "source_file": "sample.log",
                "line_number": 10,
            },
            {
                "type": "traffic",
                "subtype": "forward",
                "fields_json": json.dumps({
                    "type": "traffic",
                    "subtype": "forward",
                    "action": "accept",
                }),
                "source_file": "sample.log",
                "line_number": 11,
            },
        ])
        self.write_rules([
            {
                "rule_id": "AUTH-001",
                "name": "Failed login",
                "category": "authentication",
                "severity": "medium",
                "description": "Failed admin login",
                "log_types": ["event|system"],
                "conditions": [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "status", "op": "eq", "value": "failed"},
                ],
                "evidence_fields": ["srcip", "status"],
                "mitre_techniques": ["T1110"],
            },
            {
                "rule_id": "NET-001",
                "name": "Denied traffic",
                "category": "network_traffic",
                "severity": "low",
                "description": "Denied forward traffic",
                "log_types": ["traffic|forward"],
                "conditions": [
                    {"field": "action", "op": "in", "value": ["deny", "drop"]},
                ],
            },
        ])

        run(str(self.input_path), str(self.rules_path), str(self.output_path), batch_size=1)

        table = pq.read_table(self.output_path)
        self.assertEqual(table.num_rows, 1)
        detection = table.to_pylist()[0]
        self.assertEqual(detection["rule_id"], "AUTH-001")
        self.assertEqual(detection["source_file"], "sample.log")
        self.assertEqual(detection["line_number"], 10)
        self.assertEqual(detection["eventtime"], "1700000000")
        self.assertEqual(
            json.loads(detection["evidence"]),
            {"srcip": "192.0.2.10", "status": "failed"},
        )
        self.assertEqual(json.loads(detection["mitre_techniques"]), ["T1110"])

    def test_multiple_output_batches_keep_every_match(self):
        event_count = 4200
        self.write_events([
            {
                "type": "event",
                "subtype": "system",
                "fields_json": json.dumps({
                    "type": "event",
                    "subtype": "system",
                    "action": "login",
                    "status": "failed",
                    "srcip": "192.0.2.10",
                }),
                "source_file": "sample.log",
                "line_number": line_number,
            }
            for line_number in range(1, event_count + 1)
        ])
        self.write_rules([
            {
                "rule_id": "AUTH-001",
                "name": "Failed login",
                "category": "authentication",
                "severity": "medium",
                "description": "Failed admin login",
                "log_types": ["event|system"],
                "conditions": [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "status", "op": "eq", "value": "failed"},
                ],
            },
        ])

        run(str(self.input_path), str(self.rules_path), str(self.output_path), batch_size=256)

        metadata = pq.read_metadata(self.output_path)
        self.assertEqual(metadata.num_rows, event_count)
        self.assertGreaterEqual(metadata.num_row_groups, 2)

    def test_sequential_and_parallel_parquet_decoding_are_semantically_equal(self):
        events = []
        for line_number, (event_type, subtype, fields) in enumerate([
            ("event", "system", {"action": "login", "status": "failed", "srcip": "192.0.2.1"}),
            ("event", "system", {"action": "login", "status": "failed", "srcip": "192.0.2.1"}),
            ("event", "system", {"action": "login", "status": "failed", "srcip": "192.0.2.1"}),
            ("traffic", "forward", {"bytes": "150", "message": "keep"}),
            ("traffic", "forward", {"bytes": "50", "message": "drop"}),
        ], start=1):
            events.append({
                "type": event_type,
                "subtype": subtype,
                "fields_json": json.dumps({"type": event_type, "subtype": subtype, **fields}),
                "source_file": "sample.log",
                "line_number": line_number,
            })
        self.write_events(events)
        self.write_rules([
            {
                "rule_id": "AUTH-AGG",
                "name": "Repeated failed logins",
                "category": "authentication",
                "severity": "medium",
                "description": "Thresholded login failures",
                "log_types": ["event|system"],
                "conditions": [
                    {"field": "action", "op": "eq", "value": "login"},
                    {"field": "status", "op": "eq", "value": "failed"},
                ],
                "aggregation": {"key": "srcip", "threshold": 2},
            },
            {
                "rule_id": "TRAFFIC-GENERIC",
                "name": "Large traffic",
                "category": "network",
                "severity": "low",
                "description": "Traffic above threshold",
                "log_types": ["traffic"],
                "conditions": [{"field": "bytes", "op": "gte", "value": 100}],
            },
            {
                "rule_id": "GLOBAL",
                "name": "Message exists",
                "category": "other",
                "severity": "low",
                "description": "Any event with a message",
                "conditions": [{"field": "message", "op": "exists"}],
            },
        ])

        threaded_output = self.directory / "threaded.parquet"
        sequential_output = self.directory / "sequential.parquet"
        run(
            str(self.input_path),
            str(self.rules_path),
            str(threaded_output),
            batch_size=2,
            use_threads=True,
        )
        run(
            str(self.input_path),
            str(self.rules_path),
            str(sequential_output),
            batch_size=2,
            use_threads=False,
        )

        threaded = pq.read_table(threaded_output).drop(["detection_id"]).to_pylist()
        sequential = pq.read_table(sequential_output).drop(["detection_id"]).to_pylist()
        self.assertEqual(threaded, sequential)
        self.assertEqual(
            [row["rule_id"] for row in threaded],
            ["AUTH-AGG", "AUTH-AGG", "TRAFFIC-GENERIC", "GLOBAL", "GLOBAL"],
        )


if __name__ == "__main__":
    unittest.main()
