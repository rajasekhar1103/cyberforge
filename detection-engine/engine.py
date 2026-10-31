import argparse
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass

import pyarrow as pa
import pyarrow.parquet as pq
import yaml


OUTPUT_BATCH_SIZE = 4096
INPUT_COLUMNS = ("type", "subtype", "fields_json", "source_file", "line_number")


@dataclass(frozen=True, slots=True)
class CompiledRule:
    rule: dict
    conditions: tuple
    order: int


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

    aggregation = rule.get("aggregation")
    if aggregation:
        key = aggregation["key"]
        aggregate_key = (rule["rule_id"], ev.get(key))
        count = agg_counts.get(aggregate_key, 0) + 1
        threshold = aggregation.get("threshold", 1)
        agg_counts[aggregate_key] = min(count, threshold)
        if count < threshold:
            return None
    return matched


def compile_rules(rules):
    plans = []
    by_type = defaultdict(list)
    by_pair = defaultdict(list)
    global_rules = []

    for order, rule in enumerate(rules):
        if not rule.get("enabled", True):
            continue
        plan = CompiledRule(rule, tuple(rule.get("conditions", ())), order)
        plans.append(plan)
        log_types = tuple(dict.fromkeys(
            item.split("|", 1) if "|" in item else (item, None)
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
            matching = {
                plan.order: plan
                for plan in (
                    global_rules
                    + by_type.get(event_type, ())
                    + by_pair.get(key, ())
                )
            }
            candidates_cache[key] = tuple(
                matching[index] for index in sorted(matching)
            )
        return candidates_cache[key]

    return plans, candidates


def _eval_compiled_rule(plan, ev, agg_counts):
    rule = plan.rule
    matched = []
    for condition in plan.conditions:
        if not match_condition(ev, condition):
            return None
        matched.append(condition)

    aggregation = rule.get("aggregation")
    if aggregation:
        aggregate_key = (rule["rule_id"], ev.get(aggregation["key"]))
        count = agg_counts.get(aggregate_key, 0) + 1
        threshold = aggregation.get("threshold", 1)
        agg_counts[aggregate_key] = min(count, threshold)
        if count < threshold:
            return None
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
        "confidence": rule.get("confidence", "medium"),
        "mitre_techniques": json.dumps(rule.get("mitre_techniques", [])),
    }


def run(input_path, rules_path, output_path, batch_size=5000):
    if batch_size < 1:
        raise ValueError("batch_size must be greater than zero")

    plans, candidates_for = compile_rules(load_rules(rules_path))
    schema = _make_schema()
    parquet_file = pq.ParquetFile(input_path)
    missing_columns = set(INPUT_COLUMNS).difference(parquet_file.schema_arrow.names)
    if missing_columns:
        raise ValueError(f"Input Parquet is missing required columns: {sorted(missing_columns)}")

    aggregation_counts = {}
    pending = []
    total = 0

    with pq.ParquetWriter(output_path, schema, compression="zstd") as writer:
        for batch in parquet_file.iter_batches(
            batch_size=batch_size,
            columns=list(INPUT_COLUMNS),
        ):
            columns = {
                name: batch.column(index).to_pylist()
                for index, name in enumerate(INPUT_COLUMNS)
            }
            for index in range(batch.num_rows):
                event_type = columns["type"][index]
                subtype = columns["subtype"][index]
                rule_plans = candidates_for(event_type, subtype)
                if not rule_plans:
                    continue

                fields_json = columns["fields_json"][index]
                if fields_json is None:
                    raise ValueError(
                        f"Input row {index} in a Parquet batch has null fields_json"
                    )
                ev = json.loads(fields_json)
                ev["source_file"] = columns["source_file"][index]
                ev["line_number"] = columns["line_number"][index]

                for plan in rule_plans:
                    matched = _eval_compiled_rule(plan, ev, aggregation_counts)
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

        if pending:
            writer.write_table(
                pa.Table.from_pylist(pending, schema=schema),
                row_group_size=len(pending),
            )

    print(f"detections={total}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--batch-size", type=int, default=5000)
    args = parser.parse_args()
    run(args.input, args.rules, args.output, args.batch_size)
