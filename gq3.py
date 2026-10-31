import json, duckdb
G=json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))
nodes=G["nodes"]; edges=G["edges"]
ids={n["id"] for n in nodes}
from collections import Counter
print("node types", Counter(n["type"] for n in nodes))
print("edge rels", Counter(e["rel"] for e in edges))
print("dup nodes", len(nodes)-len(ids))
ek=[(e["source"],e["target"],e["rel"]) for e in edges]
print("dup edges", len(ek)-len(set(ek)))
connected={e["source"] for e in edges}|{e["target"] for e in edges}
print("isolated", len(ids-connected))
# components undirected
import networkx as nx
Gnx=nx.Graph()
Gnx.add_nodes_from(ids)
for e in edges: Gnx.add_edge(e["source"],e["target"])
print("components", nx.number_connected_components(Gnx))
print("invalid endpoints", sum(1 for e in edges if e["source"] not in ids or e["target"] not in ids))
print("observed", sum(1 for e in edges if e.get("observed") is True), "inferred", sum(1 for e in edges if e.get("observed") is False))
# refs
D="C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet"
I="C:/Users/nsrn/AppData/Local/Temp/kilo/incidents.parquet"
c=duckdb.connect()
det_ids={r[0] for r in c.execute(f"SELECT detection_id FROM read_parquet('{D}')").fetchall()}
inc_ids={r[0] for r in c.execute(f"SELECT incident_id FROM read_parquet('{I}')").fetchall()}
det_nodes=[n["id"] for n in nodes if n["type"]=="detection"]
inc_nodes=[n["id"] for n in nodes if n["type"]=="incident"]
print("det refs missing", sum(1 for x in det_nodes if x.split(":",1)[1] not in det_ids))
print("inc refs missing", sum(1 for x in inc_nodes if x.split(":",1)[1] not in inc_ids))
print("edges missing evidence", sum(1 for e in edges if not e.get("evidence")))
print("reload counts", len(json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))["nodes"]), len(json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))["edges"]))
