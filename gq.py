import json
G=json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))
nodes=G["nodes"]; edges=G["edges"]
print("nodes",len(nodes),"edges",len(edges))
from collections import Counter
print("node types", Counter(n.get("type") for n in nodes))
print("edge rels", Counter(e.get("rel") for e in edges))
ids={n["id"] for n in nodes}
srcs={e["source"] for e in edges}; tgts={e["target"] for e in edges}
connected=srcs|tgts
print("isolated", len(ids-connected))
print("dup nodes", len(ids)-len(set(ids)))
edgekeys=[(e["source"],e["target"],e.get("rel")) for e in edges]
print("dup edges", len(edgekeys)-len(set(edgekeys)))
