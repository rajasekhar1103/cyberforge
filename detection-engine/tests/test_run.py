import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import yaml


class DetectionCliTests(unittest.TestCase):
    def test_cli_writes_detections_from_input_parquet(self):
        engine_directory = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / "events.parquet"
            rules_path = directory / "rules.yaml"
            output_path = directory / "detections.parquet"

            pq.write_table(
                pa.Table.from_pylist(
                    [{
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
                        "line_number": 1,
                    }],
                    schema=pa.schema([
                        ("type", pa.string()),
                        ("subtype", pa.string()),
                        ("fields_json", pa.string()),
                        ("source_file", pa.string()),
                        ("line_number", pa.int64()),
                    ]),
                ),
                input_path,
            )
            rules_path.write_text(
                yaml.safe_dump({
                    "rules": [{
                        "rule_id": "TEST-001",
                        "name": "Failed login",
                        "category": "authentication",
                        "severity": "medium",
                        "description": "Test failed login",
                        "log_types": ["event|system"],
                        "conditions": [
                            {"field": "action", "op": "eq", "value": "login"},
                            {"field": "status", "op": "eq", "value": "failed"},
                        ],
                    }],
                }),
                encoding="utf-8",
            )

            subprocess.run(
                [
                    sys.executable,
                    "engine.py",
                    "--input",
                    str(input_path),
                    "--rules",
                    str(rules_path),
                    "--output",
                    str(output_path),
                ],
                cwd=engine_directory,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertEqual(pq.read_metadata(output_path).num_rows, 1)


if __name__ == "__main__":
    unittest.main()
