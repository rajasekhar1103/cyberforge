content = r'''# API Design

## Endpoints

### GET /api/health
Method GET path /api/health. No params. Response {"status":"ok"}. Source: none.

### GET /api/summary
Returns counts from detections/incidents. Response counts.

### GET /api/incidents
Query: severity, srcip, username, start_time, end_time, limit (default 50, max 200), offset. Source detections? incidents parquet. Response paginated list.

### GET /api/incidents/{incident_id}
Path incident_id. Response incident + detections via incident_detections.

### GET /api/incidents/{incident_id}/timeline
Ordered by eventtime string. Preserves timestamp fields.

### GET /api/incidents/{incident_id}/graph
Filters graph.json by detection IDs of incident. Preserves observed/derived.

### GET /api/detections/{detection_id}
Returns detection row.

### GET /api/techniques
Returns mapped techniques from detections.

## Incident-to-detection lookup
Join incident_detections on incident_id then detections on detection_id.

## Graph filtering
Select nodes whose id in detection/incident set plus edges with both endpoints selected.

## Assumptions
FastAPI availability unverified.
'''
open("C:/Users/nsrn/Desktop/scaratch/docs/api-design.md","w").write(content)
print("ok")
