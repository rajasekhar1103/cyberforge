import json
G=json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))
edges=G["edges"]
from collections import Counter
print("nodes",len(G["nodes"]),"edges",len(edges))
print("observed",sum(1 for e in edges if e.get("observed") is True),"derived",sum(1 for e in edges if e.get("observed") is False))
print("missing evidence", sum(1 for e in edges if not e.get("evidence")))
print("related missing evidence", sum(1 for e in edges if e.get("rel")=="RELATED_TO_INCIDENT" and not e.get("evidence")))
