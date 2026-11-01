import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import pyarrow as pa
import pyarrow.parquet as pq
import yaml

from engine import load_rules, run


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
        fields = [
            ("type", pa.string()),
            ("subtype", pa.string()),
            ("fields_json", pa.string()),
            ("source_file", pa.string()),
            ("line_number", pa.int64()),
        ]
        if any("parse_status" in row for row in rows):
            fields.append(("parse_status", pa.string()))
        if any("parse_warnings" in row for row in rows):
            fields.append(("parse_warnings", pa.string()))
        schema = pa.schema(fields)
        pq.write_table(pa.Table.from_pylist(rows, schema=schema), self.input_path)

    def write_rules(self, rules):
        self.rules_path.write_text(
            yaml.safe_dump({"rules": rules}),
            encoding="utf-8",
        )

    def make_event(self, line_number, fields, parse_status="parsed"):
        return {
            "type": fields.get("type", "event"),
            "subtype": fields.get("subtype", "system"),
            "fields_json": json.dumps(fields),
            "source_file": "sample.log",
            "line_number": line_number,
            "parse_status": parse_status,
        }

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
        self.assertIsNone(detection["confidence"])
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

    def test_auth_rule_requires_repeated_admin_failures_from_one_source(self):
        auth_rule = next(
            rule
            for rule in load_rules(Path(__file__).parents[1] / "rules" / "detections.yaml")
            if rule["rule_id"] == "AUTH-001"
        )
        self.write_rules([auth_rule])
        base_time = 1_700_000_000_000_000_000
        rows = []

        for username, srcip, times, status in (
            ("admin", "192.0.2.1", [0, 60, 120, 180], "failed"),
            ("admin", "192.0.2.1", [200], "success"),
            ("operator", "192.0.2.2", [0, 100, 200, 300, 400], "failed"),
            ("admin", "192.0.2.3", [0, 100, 200, 300, 600, 601], "failed"),
        ):
            for offset in times:
                line_number = len(rows) + 1
                rows.append(self.make_event(line_number, {
                    "action": "login",
                    "eventtime": str(base_time + offset * 1_000_000_000),
                    "srcip": srcip,
                    "status": status,
                    "subtype": "system",
                    "type": "event",
                    "user": username,
                }))
        self.write_events(rows)

        run(str(self.input_path), str(self.rules_path), str(self.output_path))

        detections = pq.read_table(self.output_path).to_pylist()
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0]["line_number"], 15)
        self.assertEqual(detections[0]["srcip"], "192.0.2.3")
        self.assertIsNone(detections[0]["confidence"])
        self.assertEqual(json.loads(detections[0]["mitre_techniques"]), ["T1110"])
        aggregate = json.loads(detections[0]["matched_conditions"])[-1]
        self.assertEqual(aggregate["field"], "aggregation")
        self.assertEqual(aggregate["op"], "count_within")
        self.assertEqual(aggregate["value"]["observed_count"], 5)
        self.assertEqual(
            aggregate["value"]["source_event_refs"],
            [
                {"source_file": "sample.log", "line_number": line}
                for line in (11, 12, 13, 14, 15)
            ],
        )

    def test_windowed_aggregation_includes_boundary_and_limits_alert_repeats(self):
        self.write_events([
            self.make_event(line, {
                "action": "login",
                "eventtime": str(time_ns),
                "srcip": "192.0.2.1",
                "status": "failed",
            })
            for line, time_ns in (
                (1, 0),
                (2, 600_000_000_000),
                (3, 601_000_000_000),
                (4, 1_201_000_000_000),
            )
        ])
        self.write_rules([{
            "rule_id": "WINDOW-001",
            "name": "Repeated failures",
            "category": "authentication",
            "severity": "medium",
            "description": "Two failures within ten minutes",
            "log_types": ["event|system"],
            "conditions": [{"field": "status", "op": "eq", "value": "failed"}],
            "aggregation": {
                "key": "srcip",
                "threshold": 2,
                "window_seconds": 600,
            },
        }])

        run(str(self.input_path), str(self.rules_path), str(self.output_path))

        detections = pq.read_table(self.output_path).to_pylist()
        self.assertEqual([row["line_number"] for row in detections], [2, 4])
        first_aggregation = json.loads(detections[0]["matched_conditions"])[-1]
        self.assertEqual(
            first_aggregation["value"]["source_event_refs"],
            [
                {"source_file": "sample.log", "line_number": 1},
                {"source_file": "sample.log", "line_number": 2},
            ],
        )

    def test_quarantined_and_malformed_records_are_counted_and_excluded(self):
        self.write_events([
            self.make_event(1, {
                "action": "login",
                "status": "failed",
            }, parse_status="quarantined"),
            {
                "type": None,
                "subtype": None,
                "fields_json": "{}",
                "source_file": "sample.log",
                "line_number": 2,
                "parse_status": "parsed",
            },
            {
                "type": "event",
                "subtype": "system",
                "fields_json": "[]",
                "source_file": "sample.log",
                "line_number": 3,
                "parse_status": "parsed",
            },
            {
                "type": "event",
                "subtype": "system",
                "fields_json": json.dumps({"action": "login", "status": "failed"}),
                "source_file": "sample.log",
                "line_number": 4,
                "parse_status": "parsed",
                "parse_warnings": '["duplicate key: status"]',
            },
            self.make_event(5, {
                "action": "login",
                "status": "failed",
            }),
        ])
        self.write_rules([{
            "rule_id": "TEST-001",
            "name": "Failed login",
            "category": "authentication",
            "severity": "low",
            "description": "A failed login",
            "log_types": ["event|system"],
            "conditions": [{"field": "status", "op": "eq", "value": "failed"}],
        }])
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            run(str(self.input_path), str(self.rules_path), str(self.output_path))

        detections = pq.read_table(self.output_path).to_pylist()
        self.assertEqual([row["line_number"] for row in detections], [5])
        self.assertIn("quarantined=1", stderr.getvalue())
        self.assertIn("parser_warnings=1", stderr.getvalue())
        self.assertIn("malformed=2", stderr.getvalue())

    def test_unknown_parse_status_fails_with_source_location(self):
        self.write_events([
            self.make_event(7, {
                "action": "login",
                "status": "failed",
            }, parse_status="unknown"),
        ])
        self.write_rules([{
            "rule_id": "TEST-001",
            "name": "Failed login",
            "category": "authentication",
            "severity": "low",
            "description": "A failed login",
            "log_types": ["event|system"],
            "conditions": [{"field": "status", "op": "eq", "value": "failed"}],
        }])

        with self.assertRaisesRegex(ValueError, "sample.log:7"):
            run(str(self.input_path), str(self.rules_path), str(self.output_path))

    def test_aggregation_state_limit_fails_explicitly(self):
        self.write_events([
            self.make_event(line, {
                "eventtime": str(line * 1_000_000_000),
                "srcip": f"192.0.2.{line}",
                "status": "failed",
            })
            for line in (1, 2)
        ])
        self.write_rules([{
            "rule_id": "WINDOW-001",
            "name": "Repeated failures",
            "category": "authentication",
            "severity": "medium",
            "description": "Repeated failures",
            "log_types": ["event|system"],
            "conditions": [{"field": "status", "op": "eq", "value": "failed"}],
            "aggregation": {"key": "srcip", "threshold": 2, "window_seconds": 600},
        }])

        with patch("engine.MAX_AGGREGATION_KEYS", 1):
            with self.assertRaisesRegex(ValueError, "distinct keys"):
                run(str(self.input_path), str(self.rules_path), str(self.output_path))

    def test_windowed_event_state_limit_fails_explicitly(self):
        self.write_events([
            self.make_event(line, {
                "eventtime": str(line * 1_000_000_000),
                "srcip": "192.0.2.1",
                "status": "failed",
            })
            for line in (1, 2)
        ])
        self.write_rules([{
            "rule_id": "WINDOW-001",
            "name": "Repeated failures",
            "category": "authentication",
            "severity": "medium",
            "description": "Repeated failures",
            "log_types": ["event|system"],
            "conditions": [{"field": "status", "op": "eq", "value": "failed"}],
            "aggregation": {"key": "srcip", "threshold": 1, "window_seconds": 600},
        }])

        with patch("engine.MAX_AGGREGATION_EVENTS", 1):
            with self.assertRaisesRegex(ValueError, "Windowed aggregation state exceeded"):
                run(str(self.input_path), str(self.rules_path), str(self.output_path))

    def test_rule_mappings_have_authoritative_sources_and_precise_conditions(self):
        rules = load_rules(Path(__file__).parents[1] / "rules" / "detections.yaml")
        by_id = {rule["rule_id"]: rule for rule in rules}
        mapped = [
            (rule, technique)
            for rule in rules
            for technique in rule.get("mitre_techniques", [])
        ]
        for rule, technique in mapped:
            self.assertTrue(any(
                f"attack.mitre.org/techniques/{technique}/" in reference
                for reference in rule.get("references", [])
            ))

        auth = by_id["AUTH-001"]
        self.assertTrue(all(rule.get("confidence") is None for rule in rules))
        self.assertIn(
            {"field": "user", "op": "eq", "value": "admin"},
            auth["conditions"],
        )
        self.assertEqual(
            auth["aggregation"],
            {"key": "srcip", "threshold": 5, "window_seconds": 600},
        )
        self.assertNotIn("T1133", [
            technique
            for rule in rules
            for technique in rule.get("mitre_techniques", [])
        ])
        self.assertEqual(by_id["VPN-001"]["mitre_techniques"], [])

    def test_ips_severity_rules_do_not_overlap_and_antivirus_actions_are_explicit(self):
        rows = []
        for line, severity in enumerate(("medium", "high", "critical"), start=1):
            rows.append({
                "type": "utm",
                "subtype": "ips",
                "fields_json": json.dumps({
                    "action": "dropped",
                    "severity": severity,
                }),
                "source_file": "sample.log",
                "line_number": line,
            })
        rows.extend([
            {
                "type": "utm",
                "subtype": "ips",
                "fields_json": json.dumps({"action": "allowed", "severity": "critical"}),
                "source_file": "sample.log",
                "line_number": 4,
            },
            {
                "type": "utm",
                "subtype": "virus",
                "fields_json": json.dumps({"action": "blocked"}),
                "source_file": "sample.log",
                "line_number": 5,
            },
            {
                "type": "utm",
                "subtype": "virus",
                "fields_json": json.dumps({"action": "scanned"}),
                "source_file": "sample.log",
                "line_number": 6,
            },
        ])
        self.write_events(rows)
        self.write_rules(load_rules(
            Path(__file__).parents[1] / "rules" / "detections.yaml"
        ))

        run(str(self.input_path), str(self.rules_path), str(self.output_path))

        detections = pq.read_table(self.output_path).to_pylist()
        actual = [
            (row["line_number"], row["rule_id"], row["severity"])
            for row in detections
        ]
        self.assertEqual(actual, [
            (1, "IPS-001", "medium"),
            (2, "IPS-002", "high"),
            (3, "IPS-003", "critical"),
            (5, "AV-001", "high"),
        ])


if __name__ == "__main__":
    unittest.main()
