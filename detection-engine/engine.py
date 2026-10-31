import yaml, json, uuid, time, os, sys
import pyarrow as pa
import pyarrow.parquet as pq

def load_rules(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])

def match_condition(ev, cond):
    field = cond["field"]
    val = ev.get(field)
    op = cond.get("op", "eq")
    target = cond.get("value")
    if op == "eq": return val == target
    if op == "ne": return val != target
    if op == "in": return val in target
    if op == "contains": return target in (val or "")
    if op == "exists": return val is not None
    if op == "gte": 
        try: return float(val) >= float(target)
        except: return False
    if op == "lte":
        try: return float(val) <= float(target)
        except: return False
    if op == "gt":
        try: return float(val) > float(target)
        except: return False
    return False

def eval_rule(rule, ev, agg_counts):
    if not rule.get("enabled", True): return None
    lt = rule.get("log_types", [])
    if lt and (ev.get("type"), ev.get("subtype")) not in [tuple(x.split("|")) if "|" in x else (x, None) for x in lt] and ev.get("type") not in lt:
        # flexible: accept "type" or "type|subtype"
        ok=False
        for l in lt:
            if "|" in l:
                t,s=l.split("|",1)
                if ev.get("type")==t and ev.get("subtype")==s: ok=True
            else:
                if ev.get("type")==l: ok=True
        if not ok: return None
    conds = rule.get("conditions", [])
    matched = [c for c in conds if match_condition(ev, c)]
    if len(matched) != len(conds): return None
    # aggregation
    agg = rule.get("aggregation")
    if agg:
        key = agg["key"]
        gval = ev.get(key)
        agg_key = (rule["rule_id"], gval)
        agg_counts[agg_key] = agg_counts.get(agg_key,0)+1
        if agg_counts[agg_key] < agg.get("threshold",1):
            return None
    return matched

def run(input_path, rules_path, output_path, batch_size=5000):
    rules = load_rules(rules_path)
    schema = pa.schema([
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
    writer = pq.ParquetWriter(output_path, schema, compression="zstd")
    agg_counts = {}
    total=0
    pf = pq.ParquetFile(input_path)
    for batch in pf.iter_batches(batch_size=batch_size):
        df = batch.to_pydict()
        n = len(df["line_number"])
        for i in range(n):
            fields = json.loads(df["fields_json"][i])
            ev = dict(fields)
            ev["source_file"]=df["source_file"][i]
            ev["line_number"]=df["line_number"][i]
            for rule in rules:
                matched = eval_rule(rule, ev, agg_counts)
                if matched is None: continue
                det = {
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
                    "evidence": json.dumps({k: ev.get(k) for k in (rule.get("evidence_fields") or []) if ev.get(k) is not None}),
                    "matched_conditions": json.dumps([c for c in matched]),
                    "confidence": rule.get("confidence","medium"),
                    "mitre_techniques": json.dumps(rule.get("mitre_techniques", [])),
                }
                table = pa.Table.from_pylist([det], schema=schema)
                writer.write_table(table)
                total+=1
    writer.close()
    print(f"detections={total}")

if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--batch-size", type=int, default=5000)
    args=ap.parse_args()
    run(args.input, args.rules, args.output, args.batch_size)
