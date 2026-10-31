content = """# API Design

## Endpoints
### GET /api/health
Returns service status.
### GET /api/summary
Returns counts of detections/incidents.
### GET /api/incidents
Query params: severity, srcip, username, start_time, end_time, limit (default 50 max 200), offset.
### GET /api/incidents/{incident_id}
Returns incident and detections.
### GET /api/incidents/{incident_id}/timeline
Ordered by eventtime preserving timestamp fields.
### GET /api/incidents/{incident_id}/graph
Filtered graph JSON; observed/derived preserved.
### GET /api/detections/{detection_id}
Returns detection.
### GET /api/techniques
Returns MITRE mappings.

## Repository assessment
Verified dependencies: duckdb, pyarrow, pyyaml, networkx. FastAPI availability unverified.
"""
open("C:/Users/nsrn/Desktop/scaratch/docs/api-design.md","w").write(content)
print("ok")
