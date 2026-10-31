import json
G=json.load(open("C:/Users/nsrn/AppData/Local/Temp/kilo/graph.json"))
print("metadata", G["graph"])
print("node keys", list(G["nodes"][0].keys()))
print("edge keys", list(G["edges"][0].keys()))
print("first nodes", G["nodes"][:3])
print("first edges", G["edges"][:3])
