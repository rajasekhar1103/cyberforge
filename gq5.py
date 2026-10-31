import json, duckdb
G=json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))
edges=G["edges"]
from collections import Counter, defaultdict
byrel=defaultdict(lambda: Counter())
for e in edges:
    byrel[e["rel"]][e.get("observed")] += 1
for r,c in byrel.items():
    print(r, dict(c))
D="C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet"
I="C:/Users/nsrn/AppData/Local/Temp/kilo/incidents.parquet"
R="C:/Users/nsrn/AppData/Local/Temp/kilo/incident_detections.parquet"
c=duckdb.connect()
pairs={(r[0],r[1]) for r in c.execute(f"SELECT detection_id,incident_id FROM read_parquet('{R}')").fetchall()}
graph_pairs=set()
for e in edges:
    if e["rel"]=="RELATED_TO_INCIDENT":
        ds=e["source"].split(":",1)[1]; di=e["target"].split(":",1)[1]
        graph_pairs.add((ds,di))
print("graph pairs", len(graph_pairs), "parquet pairs", len(pairs))
print("missing", len(pairs-graph_pairs), "extra", len(graph_pairs-pairs))
# node refs
det_ids={r[0] for r in c.execute(f"SELECT detection_id FROM read_parquet('{D}')").fetchall()}
inc_ids={r[0] for r in c.execute(f"SELECT incident_id FROM read_parquet('{I}')").fetchall()}
det_nodes={n["id"].split(":",1)[1] for n in G["nodes"] if n["type"]=="detection"}
inc_nodes={n["id"].split(":",1)[1] for n in G["nodes"] if n["type"]=="incident"}
print("det missing", len(det_nodes-det_ids), "inc missing", len(inc_nodes-inc_ids))
