import json, uuid, argparse
import pyarrow as pa
import pyarrow.parquet as pq
import yaml

SEV_RANK={"low":1,"medium":2,"high":3,"critical":4}

def load_detections(path):
    pf=pq.ParquetFile(path)
    out=[]
    for b in pf.iter_batches(batch_size=5000):
        d=b.to_pydict()
        n=len(d["detection_id"])
        for i in range(n):
            out.append({k:d[k][i] for k in d})
    return out

def to_time(v):
    try: return int(v)
    except: return None

def cluster(dets, window):
    n=len(dets)
    parent=list(range(n))
    def find(x):
        while parent[x]!=x:
            parent[x]=parent[parent[x]]; x=parent[x]
        return x
    def union(a,b):
        ra,rb=find(a),find(b)
        if ra!=rb: parent[ra]=rb
    # index by entity
    buckets={}
    for i,d in enumerate(dets):
        for key in ["srcip"]:
            v=d.get(key)
            if v:
                buckets.setdefault((key,v),[]).append(i)
    for key, idxs in buckets.items():
        # sort by time
        idxs_sorted=sorted(idxs, key=lambda i: (to_time(dets[i].get("eventtime")) or 0))
        # chain within window
        if len(idxs_sorted)<2: continue
        # temporal
        cur=[idxs_sorted[0]]
        for a,b in zip(idxs_sorted, idxs_sorted[1:]):
            ta=to_time(dets[a].get("eventtime")); tb=to_time(dets[b].get("eventtime"))
            if ta is None or tb is None or abs(tb-ta)<=window:
                union(a,b)
            else:
                # gap too large; still same bucket but no temporal link -> don't union
                pass
    # group
    groups={}
    for i in range(n):
        groups.setdefault(find(i),[]).append(i)
    return list(groups.values())

def make_incident(dets, idxs, window):
    ds=[dets[i] for i in idxs]
    sevs=[d.get("severity","low") for d in ds]
    sev=max(sevs, key=lambda x:SEV_RANK.get(x,0))
    times=[to_time(d.get("eventtime")) for d in ds]
    valid=[t for t in times if t is not None]
    first=min(valid) if valid else None
    last=max(valid) if valid else None
    srcips=sorted({d.get("srcip") for d in ds if d.get("srcip")})
    dstips=sorted({d.get("dstip") for d in ds if d.get("dstip")})
    users=sorted({d.get("username") for d in ds if d.get("username")})
    hosts=sorted({d.get("host") for d in ds if d.get("host")})
    rules=sorted({d.get("rule_id") for d in ds})
    cats=sorted({d.get("category") for d in ds})
    reasons=[]
    # shared entities
    if len(srcips)==1 and len(ds)>1: reasons.append("shared source IP")
    if len(users)==1 and len(ds)>1: reasons.append("shared username")
    if len(cats)>1: reasons.append("multiple detection categories")
    if valid and len(valid)>1: reasons.append("temporal proximity within window")
    if not reasons: reasons.append("single detection")
    conf="high" if len(rules)>1 or len(cats)>1 else "medium"
    if len(ds)==1: conf="low"
    return {
        "incident_id": str(uuid.uuid4()),
        "title": f"Incident: {', '.join(cats)}",
        "description": f"Correlated {len(ds)} detections across {len(rules)} rules",
        "severity": sev,
        "confidence": conf,
        "first_observed": str(first) if first is not None else None,
        "last_observed": str(last) if last is not None else None,
        "detection_count": len(ds),
        "unique_source_events": len({(d.get('source_file'),d.get('line_number')) for d in ds}),
        "related_srcips": json.dumps(srcips),
        "related_dstips": json.dumps(dstips),
        "related_usernames": json.dumps(users),
        "related_hosts": json.dumps(hosts),
        "detection_ids": json.dumps([d.get("detection_id") for d in ds]),
        "correlation_reasons": json.dumps(reasons),
        "evidence_refs": json.dumps([{"source_file":d.get("source_file"),"line_number":d.get("line_number")} for d in ds]),
        "status": "open",
    }

def run(det_path, out_incidents, out_rel, window):
    dets=load_detections(det_path)
    groups=cluster(dets, window)
    inc_schema=pa.schema([
        ("incident_id",pa.string()),("title",pa.string()),("description",pa.string()),
        ("severity",pa.string()),("confidence",pa.string()),("first_observed",pa.string()),
        ("last_observed",pa.string()),("detection_count",pa.int64()),
        ("unique_source_events",pa.int64()),("related_srcips",pa.string()),
        ("related_dstips",pa.string()),("related_usernames",pa.string()),
        ("related_hosts",pa.string()),("detection_ids",pa.string()),
        ("correlation_reasons",pa.string()),("evidence_refs",pa.string()),
        ("status",pa.string()),
    ])
    rel_schema=pa.schema([("incident_id",pa.string()),("detection_id",pa.string())])
    iw=pq.ParquetWriter(out_incidents, inc_schema, compression="zstd")
    rw=pq.ParquetWriter(out_rel, rel_schema, compression="zstd")
    for g in groups:
        inc=make_incident(dets,g,window)
        iw.write_table(pa.Table.from_pylist([inc],schema=inc_schema))
        for did in json.loads(inc["detection_ids"]):
            rw.write_table(pa.Table.from_pylist([{"incident_id":inc["incident_id"],"detection_id":did}],schema=rel_schema))
    iw.close(); rw.close()
    print(f"incidents={len(groups)} detections={len(dets)}")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--detections", required=True)
    ap.add_argument("--out-incidents", required=True)
    ap.add_argument("--out-rel", required=True)
    ap.add_argument("--window", type=int, default=3600000000000)
    args=ap.parse_args()
    run(args.detections,args.out_incidents,args.out_rel,args.window)
