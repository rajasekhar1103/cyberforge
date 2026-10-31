import json, argparse, time
import networkx as nx
import pyarrow.parquet as pq

def load(path):
    out=[]
    for b in pq.ParquetFile(path).iter_batches(batch_size=5000):
        d=b.to_pydict(); n=len(d[list(d)[0]])
        for i in range(n): out.append({k:d[k][i] for k in d})
    return out

def build(det_path, inc_path, rel_path):
    dets=load(det_path); incs=load(inc_path); rels=load(rel_path)
    relmap={(r["detection_id"], r["incident_id"]): r for r in rels}
    G=nx.DiGraph()
    # nodes
    for d in dets:
        for key,ntype in [("srcip","ip"),("dstip","ip"),("username","user"),("host","host")]:
            v=d.get(key)
            if v:
                G.add_node(f"{ntype}:{v}", type=ntype, value=v)
        did=d.get("detection_id")
        G.add_node(f"det:{did}", type="detection", value=did)
        # edges
        if d.get("srcip"): G.add_edge(f"ip:{d['srcip']}", f"det:{did}", rel="OBSERVED_SOURCE", evidence=d.get("source_file"), line=d.get("line_number"), observed=True)
        if d.get("dstip"): G.add_edge(f"det:{did}", f"ip:{d['dstip']}", rel="OBSERVED_DESTINATION", evidence=d.get("source_file"), line=d.get("line_number"), observed=True)
        if d.get("username"): G.add_edge(f"det:{did}", f"user:{d['username']}", rel="ASSOCIATED_WITH_USER", evidence=d.get("source_file"), line=d.get("line_number"), observed=True)
        if d.get("host"): G.add_edge(f"det:{did}", f"host:{d['host']}", rel="OBSERVED_ON_HOST", evidence=d.get("source_file"), line=d.get("line_number"), observed=True)
        for t in json.loads(d.get("mitre_techniques") or "[]"):
            G.add_node(f"tech:{t}", type="technique", value=t)
            G.add_edge(f"det:{did}", f"tech:{t}", rel="MAPPED_TO_TECHNIQUE", evidence=d.get("source_file"), line=d.get("line_number"), observed=False)
    for inc in incs:
        iid=inc["incident_id"]
        G.add_node(f"inc:{iid}", type="incident", value=iid)
        for did in json.loads(inc["detection_ids"]):
            G.add_edge(f"det:{did}", f"inc:{iid}", rel="RELATED_TO_INCIDENT", evidence=f"detection_id={did};incident_id={iid}", line=None, observed=False)
    # incident contains detection
    for r in rels:
        pass
    return G

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--detections", required=True)
    ap.add_argument("--incidents", required=True)
    ap.add_argument("--relations", required=True)
    ap.add_argument("--out", required=True)
    args=ap.parse_args()
    t=time.time()
    G=build(args.detections,args.incidents,args.relations)
    import json as _j
    with open(args.out,"w") as f: _j.dump(nx.node_link_data(G), f)
    print("nodes",G.number_of_nodes(),"edges",G.number_of_edges(),"time",round(time.time()-t,4))
