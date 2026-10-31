# Graph Quality Review

Nodes 786, edges 1326, isolated 0, dup nodes 0, dup edges 0.
Node types: ip 271, detection 258, incident 181, user 74, host 1, technique 1.
Edge rels: OBSERVED_SOURCE 258, OBSERVED_DESTINATION 258, OBSERVED_ON_HOST 258, RELATED_TO_INCIDENT 258, ASSOCIATED_WITH_USER 147, MAPPED_TO_TECHNIQUE 147.
## Graph JSON Schema

Node keys: type, value, id
Edge keys: rel, evidence, line, observed, source, target
Metadata: {}
## Full Graph Integrity Audit

- Node types: ip 271, detection 258, incident 181, user 74, host 1, technique 1.
- Edge rels: OBSERVED_SOURCE 258, OBSERVED_DESTINATION 258, OBSERVED_ON_HOST 258, RELATED_TO_INCIDENT 258, ASSOCIATED_WITH_USER 147, MAPPED_TO_TECHNIQUE 147.
- Duplicate nodes: 0; duplicate edges: 0; isolated: 0; components: 1; invalid endpoints: 0.
- Detection refs missing: 0; incident refs missing: 0.
- Observed edges: 1326; inferred: 0.
- Edges missing evidence: 258 (RELATED_TO_INCIDENT edges have no evidence, as generated).
- Reload counts match: 786 nodes, 1326 edges.
## Relationship Semantics Audit

- RELATED_TO_INCIDENT: 258 edges; evidence missing because generator set evidence=None. Relationship is established by incident_detections.parquet (detection_id + incident_id). Can be referenced by node IDs.
- OBSERVED_SOURCE/DESTINATION/HOST: directly supported by srcip/dstip/host fields in detections.
- ASSOCIATED_WITH_USER: directly observed from username field.
- MAPPED_TO_TECHNIQUE: derived from rule YAML, not directly observed.
- observed flag: all edges marked True, including derived MAPPED_TO_TECHNIQUE and RELATED_TO_INCIDENT; flag does not distinguish derived relationships. This is an unresolved semantic issue.
## Observed vs Derived Correction

Regenerated graph: 786 nodes, 1326 edges. Observed 921, derived 405. Missing evidence 0.
## Final Graph Integrity Validation

Edge counts by rel with observed/derived:
- OBSERVED_SOURCE: observed 258
- OBSERVED_DESTINATION: observed 258
- ASSOCIATED_WITH_USER: observed 147
- OBSERVED_ON_HOST: observed 258
- MAPPED_TO_TECHNIQUE: derived 147
- RELATED_TO_INCIDENT: derived 258

RELATED_TO_INCIDENT pairs exactly match incident_detections.parquet (0 missing, 0 extra).
Detection/incident node refs all valid (0 missing).
Relationship IDs are analytical identifiers, not raw-log evidence.
