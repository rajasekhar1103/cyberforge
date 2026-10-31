import argparse
import json
import tempfile
import uuid
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq


SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
READ_BATCH_SIZE = 4096
WRITE_BATCH_SIZE = 4096
INCIDENT_SCHEMA = pa.schema([
    ("incident_id", pa.string()),
    ("title", pa.string()),
    ("description", pa.string()),
    ("severity", pa.string()),
    ("confidence", pa.string()),
    ("first_observed", pa.string()),
    ("last_observed", pa.string()),
    ("detection_count", pa.int64()),
    ("unique_source_events", pa.int64()),
    ("related_srcips", pa.string()),
    ("related_dstips", pa.string()),
    ("related_usernames", pa.string()),
    ("related_hosts", pa.string()),
    ("detection_ids", pa.string()),
    ("correlation_reasons", pa.string()),
    ("evidence_refs", pa.string()),
    ("status", pa.string()),
])
RELATION_SCHEMA = pa.schema([
    ("incident_id", pa.string()),
    ("detection_id", pa.string()),
])


def to_time(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class IncidentAccumulator:
    def __init__(self):
        self.incident_id = str(uuid.uuid4())
        self.detection_count = 0
        self.max_severity = "low"
        self.categories = set()
        self.rules = set()
        self.srcips = set()
        self.dstips = set()
        self.usernames = set()
        self.hosts = set()
        self.detection_ids = []
        self.evidence_refs = []
        self.source_events = set()
        self.first_time = None
        self.last_time = None
        self.valid_time_count = 0

    def add(self, detection):
        self.detection_count += 1
        severity = detection.get("severity") or "low"
        if SEV_RANK.get(severity, 0) > SEV_RANK.get(self.max_severity, 0):
            self.max_severity = severity

        for field, values in (
            ("category", self.categories),
            ("rule_id", self.rules),
            ("srcip", self.srcips),
            ("dstip", self.dstips),
            ("username", self.usernames),
            ("host", self.hosts),
        ):
            value = detection.get(field)
            if value:
                values.add(value)

        detection_id = detection.get("detection_id")
        self.detection_ids.append(detection_id)
        source_file = detection.get("source_file")
        line_number = detection.get("line_number")
        self.source_events.add((source_file, line_number))
        self.evidence_refs.append({
            "source_file": source_file,
            "line_number": line_number,
        })

        event_time = to_time(detection.get("eventtime"))
        if event_time is not None:
            self.valid_time_count += 1
            self.first_time = (
                event_time if self.first_time is None
                else min(self.first_time, event_time)
            )
            self.last_time = (
                event_time if self.last_time is None
                else max(self.last_time, event_time)
            )

    def to_row(self):
        reasons = []
        if len(self.srcips) == 1 and self.detection_count > 1:
            reasons.append("shared source IP")
        if len(self.usernames) == 1 and self.detection_count > 1:
            reasons.append("shared username")
        if len(self.categories) > 1:
            reasons.append("multiple detection categories")
        if self.valid_time_count > 1:
            reasons.append("temporal proximity within window")
        if not reasons:
            reasons.append("single detection")

        confidence = "high" if len(self.rules) > 1 or len(self.categories) > 1 else "medium"
        if self.detection_count == 1:
            confidence = "low"

        return {
            "incident_id": self.incident_id,
            "title": f"Incident: {', '.join(sorted(self.categories))}",
            "description": (
                f"Correlated {self.detection_count} detections across "
                f"{len(self.rules)} rules"
            ),
            "severity": self.max_severity,
            "confidence": confidence,
            "first_observed": (
                str(self.first_time) if self.first_time is not None else None
            ),
            "last_observed": (
                str(self.last_time) if self.last_time is not None else None
            ),
            "detection_count": self.detection_count,
            "unique_source_events": len(self.source_events),
            "related_srcips": json.dumps(sorted(self.srcips)),
            "related_dstips": json.dumps(sorted(self.dstips)),
            "related_usernames": json.dumps(sorted(self.usernames)),
            "related_hosts": json.dumps(sorted(self.hosts)),
            "detection_ids": json.dumps(self.detection_ids),
            "correlation_reasons": json.dumps(reasons),
            "evidence_refs": json.dumps(self.evidence_refs),
            "status": "open",
        }


def _flush_rows(writer, rows, schema):
    if rows:
        writer.write_table(
            pa.Table.from_pylist(rows, schema=schema),
            row_group_size=len(rows),
        )
        rows.clear()


def run(
    det_path,
    out_incidents,
    out_rel,
    window,
    memory_limit="512MB",
    temp_directory=None,
):
    if window < 0:
        raise ValueError("window must be non-negative")
    if temp_directory is None:
        temp_directory = Path(tempfile.gettempdir()) / "cyberforge-correlation"
    temp_directory = Path(temp_directory)
    temp_directory.mkdir(parents=True, exist_ok=True)

    connection = duckdb.connect(database=":memory:")
    try:
        connection.execute("SET memory_limit = ?", [memory_limit])
        connection.execute("SET threads = 2")
        connection.execute("SET temp_directory = ?", [str(temp_directory)])
        query = """
            SELECT detection_id, rule_id, category, severity, srcip, dstip,
                   username, host, eventtime, source_file, line_number,
                   TRY_CAST(eventtime AS HUGEINT) AS _event_time
            FROM read_parquet(?)
            ORDER BY srcip ASC NULLS LAST,
                     COALESCE(_event_time, CAST(0 AS HUGEINT)) ASC,
                     detection_id ASC
        """
        cursor = connection.execute(query, [str(det_path)])

        incident_rows = []
        relation_rows = []
        incident_count = 0
        detection_count = 0
        current_srcip = None
        previous_time = None
        current_incident = None

        with (
            pq.ParquetWriter(
                out_incidents,
                INCIDENT_SCHEMA,
                compression="zstd",
            ) as incident_writer,
            pq.ParquetWriter(
                out_rel,
                RELATION_SCHEMA,
                compression="zstd",
            ) as relation_writer,
        ):
            def flush_incident():
                nonlocal current_incident, incident_count
                if current_incident is None:
                    return
                incident_rows.append(current_incident.to_row())
                incident_id = current_incident.incident_id
                for detection_id in current_incident.detection_ids:
                    relation_rows.append({
                        "incident_id": incident_id,
                        "detection_id": detection_id,
                    })
                    if len(relation_rows) >= WRITE_BATCH_SIZE:
                        _flush_rows(relation_writer, relation_rows, RELATION_SCHEMA)
                incident_count += 1
                current_incident = None
                if len(incident_rows) >= WRITE_BATCH_SIZE:
                    _flush_rows(incident_writer, incident_rows, INCIDENT_SCHEMA)

            for rows in iter(lambda: cursor.fetchmany(READ_BATCH_SIZE), []):
                for row in rows:
                    (
                        detection_id,
                        rule_id,
                        category,
                        severity,
                        srcip,
                        dstip,
                        username,
                        host,
                        eventtime,
                        source_file,
                        line_number,
                        event_time,
                    ) = row
                    detection_count += 1

                    if not srcip:
                        flush_incident()
                        singleton = IncidentAccumulator()
                        singleton.add({
                            "detection_id": detection_id,
                            "rule_id": rule_id,
                            "category": category,
                            "severity": severity,
                            "srcip": srcip,
                            "dstip": dstip,
                            "username": username,
                            "host": host,
                            "eventtime": eventtime,
                            "source_file": source_file,
                            "line_number": line_number,
                        })
                        current_incident = singleton
                        flush_incident()
                        previous_time = None
                        continue

                    if current_srcip != srcip:
                        flush_incident()
                        current_srcip = srcip
                        previous_time = None

                    if (
                        current_incident is not None
                        and previous_time is not None
                        and event_time is not None
                        and abs(event_time - previous_time) > window
                    ):
                        flush_incident()

                    if current_incident is None:
                        current_incident = IncidentAccumulator()
                    current_incident.add({
                        "detection_id": detection_id,
                        "rule_id": rule_id,
                        "category": category,
                        "severity": severity,
                        "srcip": srcip,
                        "dstip": dstip,
                        "username": username,
                        "host": host,
                        "eventtime": eventtime,
                        "source_file": source_file,
                        "line_number": line_number,
                    })
                    previous_time = event_time

            flush_incident()
            _flush_rows(incident_writer, incident_rows, INCIDENT_SCHEMA)
            _flush_rows(relation_writer, relation_rows, RELATION_SCHEMA)
    finally:
        connection.close()

    print(f"incidents={incident_count} detections={detection_count}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--detections", required=True)
    parser.add_argument("--out-incidents", required=True)
    parser.add_argument("--out-rel", required=True)
    parser.add_argument("--window", type=int, default=3600000000000)
    parser.add_argument("--memory-limit", default="512MB")
    parser.add_argument("--temp-directory")
    args = parser.parse_args()
    run(
        args.detections,
        args.out_incidents,
        args.out_rel,
        args.window,
        args.memory_limit,
        args.temp_directory,
    )
