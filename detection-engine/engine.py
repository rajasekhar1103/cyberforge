import argparse
import json
import sys
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass

import pyarrow as pa
import pyarrow.parquet as pq
import yaml


OUTPUT_BATCH_SIZE = 4096
INPUT_COLUMNS = ("type", "subtype", "fields_json", "source_file", "line_number")
MAX_AGGREGATION_KEYS = 100_000
MAX_AGGREGATION_EVENTS = 1_000_000
_AGGREGATION_EVENT_COUNT_KEY = object()


@dataclass(frozen=True, slots=True)
class CompiledRule:
    rule: dict
    conditions: tuple
    order: int


def _validate_aggregation(rule):
    aggregation = rule.get("aggregation")
    if aggregation is None:
        return
    if not isinstance(aggregation, dict):
        raise ValueError(f"{rule.get('rule_id', '<unknown>')} aggregation must be a mapping")
    if not isinstance(aggregation.get("key"), str) or not aggregation["key"]:
        raise ValueError(f"{rule.get('rule_id', '<unknown>')} aggregation needs a key")
    threshold = aggregation.get("threshold", 1)
    if type(threshold) is not int or threshold < 1:
        raise ValueError(
            f"{rule.get('rule_id', '<unknown>')} aggregation threshold must be a positive integer"
        )
    window_seconds = aggregation.get("window_seconds")
    if window_seconds is not None and (
        type(window_seconds) is not int or window_seconds < 1
    ):
        raise ValueError(
            f"{rule.get('rule_id', '<unknown>')} aggregation window_seconds "
            "must be a positive integer"
        )
    if window_seconds is not None and threshold > MAX_AGGREGATION_EVENTS:
        raise ValueError(
            f"{rule.get('rule_id', '<unknown>')} aggregation threshold exceeds "
            f"the {MAX_AGGREGATION_EVENTS}-event state limit"
        )


def _aggregation_matches(rule, ev, aggregation_state, aggregation_stats=None):
    aggregation = rule.get("aggregation")
    if not aggregation:
        return True, None

    key_value = ev.get(aggregation["key"])
    if key_value is None or key_value == "":
        if aggregation_stats is not None:
            aggregation_stats["missing_key"] += 1
        return False, None
    try:
        hash(key_value)
    except TypeError:
        if aggregation_stats is not None:
            aggregation_stats["invalid_key"] += 1
        return False, None

    aggregate_key = (rule["rule_id"], key_value)
    threshold = aggregation.get("threshold", 1)
    window_seconds = aggregation.get("window_seconds")
    key_count = len(aggregation_state) - int(
        _AGGREGATION_EVENT_COUNT_KEY in aggregation_state
    )

    if window_seconds is None:
        count = aggregation_state.get(aggregate_key, 0) + 1
        if aggregate_key not in aggregation_state:
            if key_count >= MAX_AGGREGATION_KEYS:
                raise ValueError(
                    f"Aggregation state exceeded {MAX_AGGREGATION_KEYS} distinct keys"
                )
        aggregation_state[aggregate_key] = min(count, threshold)
        if count < threshold:
            return False, None
        return True, {
            "field": "aggregation",
            "op": "count",
            "value": {
                "key": aggregation["key"],
                "threshold": threshold,
                "window_seconds": None,
            },
        }

    event_time = ev.get("eventtime")
    if isinstance(event_time, int) and not isinstance(event_time, bool):
        pass
    elif isinstance(event_time, str):
        try:
            event_time = int(event_time)
        except ValueError:
            event_time = None
    else:
        event_time = None
    if event_time is None:
        if aggregation_stats is not None:
            aggregation_stats["missing_eventtime"] += 1
        return False, None

    window_state = aggregation_state.get(aggregate_key)
    if window_state is None:
        if key_count >= MAX_AGGREGATION_KEYS:
            raise ValueError(
                f"Aggregation state exceeded {MAX_AGGREGATION_KEYS} distinct keys"
            )
        window_state = {"history": deque(), "last_alert": None}
        aggregation_state[aggregate_key] = window_state
    history = window_state["history"]

    if history and event_time < history[-1][0]:
        if aggregation_stats is not None:
            aggregation_stats["out_of_order_resets"] += 1
        aggregation_state[_AGGREGATION_EVENT_COUNT_KEY] = (
            aggregation_state.get(_AGGREGATION_EVENT_COUNT_KEY, 0) - len(history)
        )
        history.clear()
        window_state["last_alert"] = None

    window_ns = window_seconds * 1_000_000_000
    while history and event_time - history[0][0] > window_ns:
        history.popleft()
        aggregation_state[_AGGREGATION_EVENT_COUNT_KEY] -= 1
    if aggregation_state.get(_AGGREGATION_EVENT_COUNT_KEY, 0) >= MAX_AGGREGATION_EVENTS:
        raise ValueError(
            f"Windowed aggregation state exceeded {MAX_AGGREGATION_EVENTS} events"
        )
    history.append((
        event_time,
        ev.get("source_file"),
        ev.get("line_number"),
    ))
    aggregation_state[_AGGREGATION_EVENT_COUNT_KEY] = (
        aggregation_state.get(_AGGREGATION_EVENT_COUNT_KEY, 0) + 1
    )
    while len(history) > threshold:
        history.popleft()
        aggregation_state[_AGGREGATION_EVENT_COUNT_KEY] -= 1
    last_alert = window_state["last_alert"]
    if (
        len(history) >= threshold
        and (last_alert is None or event_time - last_alert > window_ns)
    ):
        window_state["last_alert"] = event_time
        return True, {
            "field": "aggregation",
            "op": "count_within",
            "value": {
                "key": aggregation["key"],
                "threshold": threshold,
                "window_seconds": window_seconds,
                "observed_count": len(history),
                "source_event_refs": [
                    {"source_file": source_file, "line_number": line_number}
                    for _, source_file, line_number in history
                ],
            },
        }
    return False, None


def load_rules(path):
    with open(path, encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("Rules file must contain a 'rules' list")
    return data["rules"]


def match_condition(ev, cond):
    field = cond["field"]
    val = ev.get(field)
    op = cond.get("op", "eq")
    target = cond.get("value")
    if op == "eq":
        return val == target
    if op == "ne":
        return val != target
    if op == "in":
        return val in target
    if op == "contains":
        return target in (val or "")
    if op == "exists":
        return val is not None
    if op == "gte":
        try:
            return float(val) >= float(target)
        except (TypeError, ValueError):
            return False
    if op == "lte":
        try:
            return float(val) <= float(target)
        except (TypeError, ValueError):
            return False
    if op == "gt":
        try:
            return float(val) > float(target)
        except (TypeError, ValueError):
            return False
    return False


def eval_rule(rule, ev, agg_counts):
    if not rule.get("enabled", True):
        return None
    log_types = rule.get("log_types", [])
    if log_types:
        matches_type = any(
            (ev.get("type") == value and ev.get("subtype") == subtype)
            if subtype is not None
            else ev.get("type") == value
            for value, subtype in (
                item.split("|", 1) if "|" in item else (item, None)
                for item in log_types
            )
        )
        if not matches_type:
            return None

    conditions = rule.get("conditions", [])
    matched = [condition for condition in conditions if match_condition(ev, condition)]
    if len(matched) != len(conditions):
        return None

    aggregation_matched, _ = _aggregation_matches(rule, ev, agg_counts)
    if not aggregation_matched:
        return None
    return matched


def compile_rules(rules):
    plans = []
    by_type = defaultdict(list)
    by_pair = defaultdict(list)
    global_rules = []

    for order, rule in enumerate(rules):
        _validate_aggregation(rule)
        if not rule.get("enabled", True):
            continue
        plan = CompiledRule(rule, tuple(rule.get("conditions", ())), order)
        plans.append(plan)
        log_types = tuple(dict.fromkeys(
            tuple(item.split("|", 1)) if "|" in item else (item, None)
            for item in rule.get("log_types", ())
        ))
        if not log_types:
            global_rules.append(plan)
            continue
        for event_type, subtype in log_types:
            if subtype is None:
                by_type[event_type].append(plan)
            else:
                by_pair[(event_type, subtype)].append(plan)

    candidates_cache = {}

    def candidates(event_type, subtype):
        key = (event_type, subtype)
        if key not in candidates_cache:
            matching = {}
            for plan in (
                *global_rules,
                *by_type.get(event_type, ()),
                *by_pair.get(key, ()),
            ):
                matching[plan.order] = plan
            candidates_cache[key] = tuple(
                matching[index] for index in sorted(matching)
            )
        return candidates_cache[key]

    return plans, candidates


def _eval_compiled_rule(plan, ev, agg_counts, aggregation_stats):
    rule = plan.rule
    matched = []
    for condition in plan.conditions:
        if not match_condition(ev, condition):
            return None
        matched.append(condition)

    aggregation_matched, aggregation_evidence = _aggregation_matches(
        rule, ev, agg_counts, aggregation_stats
    )
    if not aggregation_matched:
        return None
    if aggregation_evidence is not None:
        matched.append(aggregation_evidence)
    return matched


def _make_schema():
    return pa.schema([
        ("detection_id", pa.string()),
        ("rule_id", pa.string()),
        ("rule_name", pa.string()),
        ("category", pa.string()),
        ("severity", pa.string()),
        ("description", pa.string()),
        ("srcip", pa.string()),
        ("dstip", pa.string()),
        ("username", pa.string()),
        ("host", pa.string()),
        ("eventtime", pa.string()),
        ("date", pa.string()),
        ("time", pa.string()),
        ("tz", pa.string()),
        ("source_file", pa.string()),
        ("line_number", pa.int64()),
        ("evidence", pa.string()),
        ("matched_conditions", pa.string()),
        ("confidence", pa.string()),
        ("mitre_techniques", pa.string()),
    ])


def _make_detection(rule, ev, matched):
    evidence = {
        key: ev.get(key)
        for key in (rule.get("evidence_fields") or ())
        if ev.get(key) is not None
    }
    return {
        "detection_id": str(uuid.uuid4()),
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "category": rule["category"],
        "severity": rule["severity"],
        "description": rule["description"],
        "srcip": ev.get("srcip"),
        "dstip": ev.get("dstip"),
        "username": ev.get("user") or ev.get("username"),
        "host": ev.get("devname") or ev.get("hostname"),
        "eventtime": ev.get("eventtime"),
        "date": ev.get("date"),
        "time": ev.get("time"),
        "tz": ev.get("tz"),
        "source_file": ev["source_file"],
        "line_number": ev["line_number"],
        "evidence": json.dumps(evidence),
        "matched_conditions": json.dumps(matched),
        "confidence": rule.get("confidence"),
        "mitre_techniques": json.dumps(rule.get("mitre_techniques", [])),
    }


def run(input_path, rules_path, output_path, batch_size=5000, use_threads=True):
    if batch_size < 1:
        raise ValueError("batch_size must be greater than zero")

    _, candidates_for = compile_rules(load_rules(rules_path))
    schema = _make_schema()
    parquet_file = pq.ParquetFile(input_path)
    missing_columns = set(INPUT_COLUMNS).difference(parquet_file.schema_arrow.names)
    if missing_columns:
        raise ValueError(f"Input Parquet is missing required columns: {sorted(missing_columns)}")
    has_parse_status = "parse_status" in parquet_file.schema_arrow.names
    has_parse_warnings = "parse_warnings" in parquet_file.schema_arrow.names
    input_columns = list(INPUT_COLUMNS)
    if has_parse_status:
        input_columns.append("parse_status")
    if has_parse_warnings:
        input_columns.append("parse_warnings")

    aggregation_counts = {}
    aggregation_stats = {
        "missing_key": 0,
        "invalid_key": 0,
        "missing_eventtime": 0,
        "out_of_order_resets": 0,
    }
    pending = []
    total = 0
    processed_rows = 0
    parsed_rows = 0
    quarantined_rows = 0
    parser_warning_rows = 0
    malformed_rows = 0
    total_rows = parquet_file.metadata.num_rows
    started_at = time.perf_counter()
    last_progress_at = started_at

    with pq.ParquetWriter(output_path, schema, compression="zstd") as writer:
        for batch in parquet_file.iter_batches(
            batch_size=batch_size,
            columns=input_columns,
            use_threads=use_threads,
        ):
            columns = {
                name: batch.column(index).to_pylist()
                for index, name in enumerate(input_columns)
            }
            for index in range(batch.num_rows):
                source_file = columns["source_file"][index]
                line_number = columns["line_number"][index]
                if has_parse_status:
                    parse_status = columns["parse_status"][index]
                    if parse_status == "quarantined":
                        quarantined_rows += 1
                        continue
                    if parse_status != "parsed":
                        raise ValueError(
                            f"Unsupported parse_status {parse_status!r} at "
                            f"{source_file}:{line_number}"
                        )
                parsed_rows += 1

                if has_parse_warnings:
                    parse_warnings = columns["parse_warnings"][index]
                    if parse_warnings:
                        try:
                            warnings = json.loads(parse_warnings)
                        except json.JSONDecodeError:
                            malformed_rows += 1
                            continue
                        if not isinstance(warnings, list):
                            malformed_rows += 1
                            continue
                        if warnings:
                            parser_warning_rows += 1
                            continue

                event_type = columns["type"][index]
                subtype = columns["subtype"][index]
                fields_json = columns["fields_json"][index]
                if (
                    not isinstance(event_type, str)
                    or not event_type
                    or not isinstance(subtype, str)
                    or not subtype
                    or not isinstance(fields_json, str)
                    or not isinstance(source_file, str)
                    or not source_file
                    or type(line_number) is not int
                    or line_number < 1
                ):
                    malformed_rows += 1
                    continue

                rule_plans = candidates_for(event_type, subtype)
                if not rule_plans:
                    continue

                try:
                    ev = json.loads(fields_json)
                except json.JSONDecodeError:
                    malformed_rows += 1
                    continue
                if not isinstance(ev, dict):
                    malformed_rows += 1
                    continue
                ev["source_file"] = source_file
                ev["line_number"] = line_number

                for plan in rule_plans:
                    matched = _eval_compiled_rule(
                        plan, ev, aggregation_counts, aggregation_stats
                    )
                    if matched is None:
                        continue
                    pending.append(_make_detection(plan.rule, ev, matched))
                    total += 1
                    if len(pending) >= OUTPUT_BATCH_SIZE:
                        writer.write_table(
                            pa.Table.from_pylist(pending, schema=schema),
                            row_group_size=OUTPUT_BATCH_SIZE,
                        )
                        pending.clear()

            processed_rows += batch.num_rows
            now = time.perf_counter()
            if now - last_progress_at >= 1.0 or processed_rows == total_rows:
                elapsed = now - started_at
                rows_per_second = processed_rows / elapsed if elapsed else 0.0
                fraction = processed_rows / total_rows if total_rows else 1.0
                remaining_seconds = (
                    (total_rows - processed_rows) / rows_per_second
                    if rows_per_second
                    else 0.0
                )
                hours, remainder = divmod(int(remaining_seconds), 3600)
                minutes, seconds = divmod(remainder, 60)
                print(
                    f"\rDetection progress: {fraction * 100:5.1f}% | "
                    f"{processed_rows:,}/{total_rows:,} rows | "
                    f"{rows_per_second:,.0f} rows/s | "
                    f"ETA {hours:02}:{minutes:02}:{seconds:02}",
                    file=sys.stderr,
                    flush=True,
                )
                last_progress_at = now

        if pending:
            writer.write_table(
                pa.Table.from_pylist(pending, schema=schema),
                row_group_size=len(pending),
            )

    elapsed = time.perf_counter() - started_at
    print(
        f"detection complete: rows={processed_rows} parsed={parsed_rows} "
        f"quarantined={quarantined_rows if has_parse_status else 'unavailable'} "
        f"parser_warnings={parser_warning_rows} malformed={malformed_rows} "
        f"detections={total} "
        f"aggregation_missing_key={aggregation_stats['missing_key']} "
        f"aggregation_invalid_key={aggregation_stats['invalid_key']} "
        f"aggregation_missing_eventtime={aggregation_stats['missing_eventtime']} "
        f"aggregation_out_of_order_resets={aggregation_stats['out_of_order_resets']} "
        f"parse_status_column={'present' if has_parse_status else 'absent'} "
        f"elapsed={elapsed:.2f}s",
        file=sys.stderr,
    )
    print(f"detections={total}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument(
        "--sequential-read",
        action="store_false",
        dest="use_threads",
        help="Disable PyArrow's bounded parallel Parquet decoding",
    )
    parser.set_defaults(use_threads=True)
    args = parser.parse_args()
    run(args.input, args.rules, args.output, args.batch_size, args.use_threads)
