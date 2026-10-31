p="C:/Users/nsrn/Desktop/scaratch/graph-engine/graph.py"
s=open(p).read()
# add rel lookup
s=s.replace(
'''    dets=load(det_path); incs=load(inc_path); rels=load(rel_path)
    G=nx.DiGraph()''',
'''    dets=load(det_path); incs=load(inc_path); rels=load(rel_path)
    relmap={(r["detection_id"], r["incident_id"]): r for r in rels}
    G=nx.DiGraph()''')
# RELATED_TO_INCIDENT edge
s=s.replace(
'''        for did in json.loads(inc["detection_ids"]):
            G.add_edge(f"det:{did}", f"inc:{iid}", rel="RELATED_TO_INCIDENT", evidence=None, line=None, observed=True)''',
'''        for did in json.loads(inc["detection_ids"]):
            G.add_edge(f"det:{did}", f"inc:{iid}", rel="RELATED_TO_INCIDENT", evidence=f"detection_id={did};incident_id={iid}", line=None, observed=False)''')
# MAPPED_TO_TECHNIQUE
s=s.replace(
'''            G.add_edge(f"det:{did}", f"tech:{t}", rel="MAPPED_TO_TECHNIQUE", evidence=d.get("source_file"), line=d.get("line_number"), observed=True)''',
'''            G.add_edge(f"det:{did}", f"tech:{t}", rel="MAPPED_TO_TECHNIQUE", evidence=d.get("source_file"), line=d.get("line_number"), observed=False)''')
open(p,"w").write(s)
print("done")
