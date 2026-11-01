# API Design

## Status and evidence

This is a proposed HTTP contract, not an implemented API. The repository documents FastAPI as a planned component; it contains no FastAPI application or route handlers. Endpoint behavior, parameter limits, error envelopes, cursor behavior, and response envelopes below are design decisions that require approval.

The examples use actual values inspected in:

- `C:\Users\nsrn\AppData\Local\Temp\kilo\detections.parquet` (258 rows)
- `C:\Users\nsrn\AppData\Local\Temp\kilo\incidents.parquet` (181 rows)
- `C:\Users\nsrn\AppData\Local\Temp\kilo\incident_detections.parquet` (258 rows)
- `C:\Users\nsrn\AppData\Local\Temp\kilo\graph.json` (786 nodes, 1,326 edges)

The response envelopes, health response, pagination cursor, and errors are illustrative proposed API values. The IDs and record values shown in successful analytics examples are copied from those generated artifacts, not invented. These artifacts are a temporary 1,000-input-record sample, not a production deployment. The top-level `out.parquet` was not readable as Parquet, so no API example is based on it.

**Detection caveat:** these stored examples predate the current rule audit. In particular,
the historical AUTH-001 example below is a single failed login and must not be treated
as a valid output of the current rule, which requires five failed admin logins from one
source within 600 seconds. Current confidence is `null` until calibrated, VPN-001/T1133
is no longer an active mapping, and correlation output represents an observation
cluster rather than a confirmed incident. These legacy records illustrate API shape
only. The historical graph also contains a T1110 mapping sourced from one failed-login
row; that mapping is unsupported under the current policy and must not be treated as a
valid current graph relationship. The detection-detail example below uses a current
row from `D:\cyberforge-run-20261101-0810\accuracy-updated-strict.parquet`.

## Conventions

- Base path: `/api`; JSON UTF-8 responses.
- Use lower-case severity values: `low`, `medium`, `high`, `critical`.
- IDs are canonical UUID strings as produced by the current analytics sample.
- `eventtime`, `first_observed`, and `last_observed` are decimal strings, not JSON numbers or ISO timestamps. The parser and correlation design retain the existing timestamp representation; the API does not timezone-convert or round it.
- Stored JSON text columns (`evidence`, `matched_conditions`, `mitre_techniques`, incident arrays, and `evidence_refs`) are decoded to JSON values in API responses. The original Parquet values remain strings.
- All successful list responses include `items` and `pagination`. Errors use the common envelope in [Errors](#common-errors).
- Request parameters are bound values, never interpolated into SQL. Detailed query patterns are in [api-performance-plan.md](./api-performance-plan.md).
- Any data query can also return `504 query_timeout` if the approved request deadline expires.

## Endpoint index

| # | Method and path | Purpose |
|---:|---|---|
| 1 | `GET /api/health` | Process and configured-store health |
| 2 | `GET /api/summary` | Dataset totals and severity/category counts |
| 3 | `GET /api/incidents` | Filtered, paginated incident list |
| 4 | `GET /api/incidents/{incident_id}` | Incident and paginated linked detections |
| 5 | `GET /api/incidents/{incident_id}/timeline` | Chronological linked detections |
| 6 | `GET /api/incidents/{incident_id}/graph` | Bounded incident-centered graph subgraph |
| 7 | `GET /api/detections/{detection_id}` | Detection lookup |
| 8 | `GET /api/techniques` | Distinct mapped technique IDs and counts |

---

## 1. Health

**Method/path:** `GET /api/health`

**Parameters:** None.

**Validation:** None.

**Data source/query:** No analytics scan. Check that the API process is responsive and that required configured Parquet/graph inputs are reachable. A process-only liveness probe should remain separate from this readiness response if orchestration requires one.

**Success — 200** (illustrative proposed response):

```json
{
  "status": "ok",
  "service": "cyberforge-api",
  "stores": {
    "detections": "ready",
    "incidents": "ready",
    "incident_detections": "ready",
    "graph": "ready"
  }
}
```

**Errors:** `503 service_unavailable` when any required configured input cannot be opened or validated, including `incident_detections.parquet`. The error body uses the common envelope. Do not return `200` with a success-shaped response when required stores are unavailable.

---

## 2. Summary

**Method/path:** `GET /api/summary`

**Parameters:** None.

**Validation:** None.

**Data source/query:** Read detection, incident, and incident-detection Parquet metadata through DuckDB. Calculate totals, counts grouped by severity/category, and unassigned detection count. Counts describe the configured snapshot; the response need not claim an atomic snapshot across files unless the deployment publishes a versioned manifest.

**Success — 200** (counts below are actual inspected sample aggregates; envelope is proposed):

```json
{
  "total_detections": 258,
  "total_incidents": 181,
  "unassigned_detections": 0,
  "detections_by_severity": {
    "low": 44,
    "medium": 153,
    "high": 40,
    "critical": 21
  },
  "incidents_by_severity": {
    "low": 42,
    "medium": 99,
    "high": 19,
    "critical": 21
  },
  "detections_by_category": {
    "authentication": 147,
    "intrusion_prevention": 48,
    "malware": 13,
    "network_traffic": 44,
    "web_filtering": 6
  }
}
```

**Errors:** `503 service_unavailable` for missing, unreadable, or inconsistent required analytics inputs; `500 internal_error` for an unexpected query failure. Error bodies use the common envelope.

---

## 3. Incident list

**Method/path:** `GET /api/incidents`

**Parameters:**

| Name | Type | Default | Validation and meaning |
|---|---|---:|---|
| `severity` | string | omitted | One of `low`, `medium`, `high`, `critical`; exact match against stored incident severity. |
| `srcip` | string | omitted | Valid IPv4 or IPv6 literal; exact textual entity match on detections linked to the incident. |
| `username` | string | omitted | Non-empty UTF-8 string, at most 256 characters; exact, case-sensitive match. |
| `start_time` | string | omitted | 1–38 decimal digits; non-negative `eventtime` value, minimum linked detection time, inclusive. |
| `end_time` | string | omitted | 1–38 decimal digits; non-negative `eventtime` value, maximum linked detection time, inclusive. |
| `limit` | integer | `50` | 1–200. |
| `offset` | integer | `0` | 0–10,000. Mutually exclusive with `cursor`. |
| `cursor` | opaque string | omitted | Keyset continuation token returned by this endpoint; mutually exclusive with non-zero `offset`. |

Reject malformed IDs/parameters with `400 invalid_parameter`; reject `start_time > end_time`. Time filters are decimal eventtime strings, not ISO-8601 values. If multiple detection filters are supplied, they must match the same linked detection. Compare `srcip` to the stored spelling after validating it as an IP literal; clients should use the stored textual form. Sort by `first_observed` descending as an exact integer value, null last, then `incident_id` ascending.

**Data source/query:** `incidents.parquet`; use `incident_detections.parquet` joined to `detections.parquet` for entity/time predicates. Count filtered incidents separately from the page query so the total remains available for an empty page. The proposed public incident object decodes stored JSON-string arrays into arrays.

**Success — 200** (incident values are actual Parquet values; pagination/cursor are illustrative):

```json
{
  "items": [
    {
      "incident_id": "a7af2703-d89b-4e32-abdd-e3093811dafb",
      "title": "Incident: authentication",
      "description": "Correlated 2 detections across 1 rules",
      "severity": "medium",
      "confidence": "medium",
      "first_observed": "1792745306564464000",
      "last_observed": "1792745405486780000",
      "detection_count": 2,
      "unique_source_events": 2,
      "related_srcips": ["209.50.167.232"],
      "related_dstips": ["10.10.99.1"],
      "related_usernames": ["admin", "raymond.tong"],
      "related_hosts": ["FGT60FTK00000000"],
      "detection_ids": [
        "fa6e7a80-4f15-4fcf-ad18-a56ef636ef61",
        "b2bf737d-75cb-47d0-abbb-fb24d0893e14"
      ],
      "correlation_reasons": [
        "shared source IP",
        "temporal proximity within window"
      ],
      "evidence_refs": [
        {
          "source_file": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
          "line_number": 4
        },
        {
          "source_file": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
          "line_number": 431
        }
      ],
      "status": "open"
    }
  ],
  "pagination": {
    "limit": 1,
    "offset": 0,
    "total": 181,
    "next_cursor": "opaque-token-example"
  }
}
```

**Errors:** `400 invalid_parameter`; `503 service_unavailable`; `500 internal_error`.

---

## 4. Incident detail and detection lookup

**Method/path:** `GET /api/incidents/{incident_id}`

**Path parameter:** `incident_id` — canonical UUID string; required.

**Query parameters:** `limit` integer, default `50`, range 1–200; `offset` integer, default `0`, range 0–10,000; or `cursor` opaque token, mutually exclusive with non-zero offset. These page the linked detections, not the incident object.

**Data source/query:** Read the incident by ID. Then look up relationships by `incident_id` in `incident_detections.parquet` and join each `detection_id` to `detections.parquet`. Order detections by exact numeric `eventtime` ascending, null last, then `detection_id`. Run a count query for linked detections. Do not trust the incident's serialized `detection_ids` as the authoritative relationship table.

**Incident-to-detection lookup algorithm:**

1. Validate and bind the incident UUID.
2. Select exactly one incident row by `incident_id`; return `404 not_found` if absent.
3. Filter the relationship Parquet by that `incident_id`.
4. Join relationship `detection_id` to `detections.detection_id`; retain only fields in the Detection contract.
5. Order by `TRY_CAST(eventtime AS HUGEINT) ASC NULLS LAST, detection_id ASC`. Keep the original `eventtime` string in the response.
6. Count all relationship rows, apply the requested limit/cursor, decode serialized JSON fields, and return the incident plus the page and its pagination metadata.
7. Treat a relationship whose detection row is missing as a data-integrity failure; report `503 data_integrity_error` and log the missing IDs rather than silently dropping the link.

**Success — 200** (the singleton incident and its detection are actual Parquet rows; pagination envelope is proposed):

```json
{
  "incident": {
    "incident_id": "01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3",
    "title": "Incident: authentication",
    "description": "Correlated 1 detections across 1 rules",
    "severity": "medium",
    "confidence": "low",
    "first_observed": "1792745341702348000",
    "last_observed": "1792745341702348000",
    "detection_count": 1,
    "unique_source_events": 1,
    "related_srcips": ["209.50.176.220"],
    "related_dstips": ["10.10.99.1"],
    "related_usernames": ["admin"],
    "related_hosts": ["FGT60FTK00000000"],
    "detection_ids": ["f906e5df-a041-420d-bac1-63d840051506"],
    "correlation_reasons": ["single detection"],
    "evidence_refs": [
      {
        "source_file": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
        "line_number": 159
      }
    ],
    "status": "open"
  },
  "detections": [
    {
      "detection_id": "f906e5df-a041-420d-bac1-63d840051506",
      "rule_id": "AUTH-001",
      "rule_name": "Repeated admin login failure",
      "category": "authentication",
      "severity": "medium",
      "description": "FortiGate event system login failure by admin",
      "srcip": "209.50.176.220",
      "dstip": "10.10.99.1",
      "username": "admin",
      "host": "FGT60FTK00000000",
      "eventtime": "1792745341702348000",
      "date": "2026-10-23",
      "time": "08:49:01",
      "tz": "+0530",
      "source_file": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line_number": 159,
      "evidence": {
        "srcip": "209.50.176.220",
        "user": "admin",
        "status": "failed",
        "reason": "name_invalid",
        "msg": "Administrator admin login failed from https(209.50.176.220) because of invalid user name"
      },
      "matched_conditions": [
        {"field": "action", "op": "eq", "value": "login"},
        {"field": "status", "op": "eq", "value": "failed"}
      ],
      "confidence": "medium",
      "mitre_techniques": ["T1110"]
    }
  ],
  "detections_pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1,
    "next_cursor": null
  }
}
```

**Errors:** `400 invalid_parameter`; `404 not_found` for an unknown incident; `503 data_integrity_error` for broken relationships or unavailable stores; `500 internal_error`.

---

## 5. Incident timeline

**Method/path:** `GET /api/incidents/{incident_id}/timeline`

**Path parameter:** `incident_id` — canonical UUID string; required.

**Query parameters:** `limit` integer, default `100`, range 1–500; `offset` integer, default `0`, range 0–10,000; or opaque `cursor`, mutually exclusive with non-zero offset.

**Data source/query:** First verify the incident exists, then use the same relation-to-detection join as incident detail. Return a compact projection of each detection (not reconstructed raw-log records). Sort by exact numeric eventtime ascending, null last, with `detection_id` as a stable tie breaker. Preserve eventtime/date/time/tz verbatim.

**Success — 200** (the timeline item is projected from the actual detection row; response wrapper is proposed):

```json
{
  "incident_id": "01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3",
  "items": [
    {
      "detection_id": "f906e5df-a041-420d-bac1-63d840051506",
      "eventtime": "1792745341702348000",
      "date": "2026-10-23",
      "time": "08:49:01",
      "tz": "+0530",
      "rule_id": "AUTH-001",
      "rule_name": "Repeated admin login failure",
      "severity": "medium",
      "srcip": "209.50.176.220",
      "dstip": "10.10.99.1",
      "username": "admin",
      "host": "FGT60FTK00000000",
      "source_file": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line_number": 159
    }
  ],
  "pagination": {
    "limit": 100,
    "offset": 0,
    "total": 1,
    "next_cursor": null
  }
}
```

**Errors:** `400 invalid_parameter`; `404 not_found`; `503 data_integrity_error` or `service_unavailable`; `500 internal_error`.

---

## 6. Incident graph

**Method/path:** `GET /api/incidents/{incident_id}/graph`

**Path parameter:** `incident_id` — canonical UUID string; required.

**Query parameters:**

| Name | Type | Default | Validation and meaning |
|---|---|---:|---|
| `depth` | integer | `1` | 1–3 graph hops from the incident/detection seed nodes. |
| `include_derived` | boolean | `true` | Include edges whose stored `observed` property is false. |
| `node_type` | repeated enum | all | Optional filter: `ip`, `user`, `host`, `technique`, `detection`, `incident`. |
| `edge_type` | repeated string | all | Optional exact relationship-name filter, at most 20 values, each at most 64 characters. |
| `max_nodes` | integer | `1000` | 1–5,000; safety limit, not silent truncation. |

**Data source/query:** Verify the incident and linked detection IDs from the incident and relationship Parquet files. Filter the existing node-link graph JSON (the current generated file is `graph.json`). If graph JSON is not present, graph reconstruction from detection/relationship Parquet is a separate proposed implementation, not verified current behavior. Query patterns are in the performance plan.

**Graph filtering algorithm (breadth-first, deterministic):**

1. Validate `incident_id`, then fetch the incident and its linked detection IDs from `incident_detections.parquet`.
2. Seed the selected-node set with `inc:{incident_id}` and `det:{detection_id}` for every linked detection. The incident record's JSON `detection_ids` is descriptive; the relation Parquet is authoritative.
3. Starting at depth zero, visit incident/detection seed nodes in sorted ID order. For each frontier node, inspect graph edges in both directions. Ignore edges with `observed == false` when `include_derived=false`; apply any `edge_type` allow-list during traversal.
4. Add unseen neighboring node IDs and advance breadth-first until `depth` is reached. Apply `node_type` to non-seed neighbors; keep required seed nodes so the requested incident context is not silently discarded.
5. If the selected node count exceeds `max_nodes`, return `413 graph_too_large` with no partial graph. Do not return a graph with dangling edges.
6. Emit the induced edge set whose source and target both occur in the selected-node set and whose edge passes the derived/relationship filters. Sort nodes by `id` and edges by `(source, target, rel)` for stable output.
7. Preserve the graph's `observed` boolean and evidence references. A `false` value means a derived relationship in the current graph contract; it must not be relabeled as observed.

**Evidence semantics:** Graph-edge `evidence` and `line` on `MAPPED_TO_TECHNIQUE` edges identify the source record that produced the detection. They establish source-record provenance only; they do not prove why the detection was mapped to a technique. `RELATED_TO_INCIDENT` evidence is a relationship reference (`detection_id` plus `incident_id`), not a raw-log citation. Analytical mapping provenance would identify the rule or mapping catalog/version and mapping rationale; the current graph does not store that provenance explicitly. Preserve `observed=false` on both derived relationship types, including `MAPPED_TO_TECHNIQUE`.

**Success — 200** (nodes and edges below are actual entries from the historical
graph.json sample; graph metadata is proposed. See the detection caveat above before
interpreting the legacy `MAPPED_TO_TECHNIQUE` edge):

```json
{
  "directed": true,
  "multigraph": false,
  "graph": {
    "incident_id": "01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3",
    "depth": 1,
    "include_derived": true
  },
  "nodes": [
    {"type": "ip", "value": "10.10.99.1", "id": "ip:10.10.99.1"},
    {"type": "user", "value": "admin", "id": "user:admin"},
    {"type": "host", "value": "FGT60FTK00000000", "id": "host:FGT60FTK00000000"},
    {"type": "technique", "value": "T1110", "id": "tech:T1110"},
    {"type": "ip", "value": "209.50.176.220", "id": "ip:209.50.176.220"},
    {
      "type": "detection",
      "value": "f906e5df-a041-420d-bac1-63d840051506",
      "id": "det:f906e5df-a041-420d-bac1-63d840051506"
    },
    {
      "type": "incident",
      "value": "01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3",
      "id": "inc:01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3"
    }
  ],
  "edges": [
    {
      "rel": "OBSERVED_SOURCE",
      "evidence": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line": 159,
      "observed": true,
      "source": "ip:209.50.176.220",
      "target": "det:f906e5df-a041-420d-bac1-63d840051506"
    },
    {
      "rel": "OBSERVED_DESTINATION",
      "evidence": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line": 159,
      "observed": true,
      "source": "det:f906e5df-a041-420d-bac1-63d840051506",
      "target": "ip:10.10.99.1"
    },
    {
      "rel": "ASSOCIATED_WITH_USER",
      "evidence": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line": 159,
      "observed": true,
      "source": "det:f906e5df-a041-420d-bac1-63d840051506",
      "target": "user:admin"
    },
    {
      "rel": "OBSERVED_ON_HOST",
      "evidence": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line": 159,
      "observed": true,
      "source": "det:f906e5df-a041-420d-bac1-63d840051506",
      "target": "host:FGT60FTK00000000"
    },
    {
      "rel": "MAPPED_TO_TECHNIQUE",
      "evidence": "C:\\Users\\nsrn\\AppData\\Local\\Temp\\kilo\\sample1000.log",
      "line": 159,
      "observed": false,
      "source": "det:f906e5df-a041-420d-bac1-63d840051506",
      "target": "tech:T1110"
    },
    {
      "rel": "RELATED_TO_INCIDENT",
      "evidence": "detection_id=f906e5df-a041-420d-bac1-63d840051506;incident_id=01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3",
      "line": null,
      "observed": false,
      "source": "det:f906e5df-a041-420d-bac1-63d840051506",
      "target": "inc:01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3"
    }
  ]
}
```

**Errors:** `400 invalid_parameter`; `404 not_found`; `413 graph_too_large` when the selected subgraph exceeds `max_nodes`; `503 service_unavailable` for missing/corrupt graph or relationship data; `500 internal_error`.

---

## 7. Detection detail

**Method/path:** `GET /api/detections/{detection_id}`

**Path parameter:** `detection_id` — canonical UUID string; required.

**Parameters:** No query parameters.

**Validation:** Invalid UUID is `400`; a syntactically valid but absent ID is `404`.

**Data source/query:** Exact lookup by `detection_id` in `detections.parquet`. Decode the three JSON-serialized fields before returning the Detection object.

**Success — 200** (current full-run detection row; JSON fields decoded):

```json
{
  "detection_id": "e9ceef79-1792-40eb-96f8-c4825c283a48",
  "rule_id": "AUTH-001",
  "rule_name": "Repeated admin login failure",
  "category": "authentication",
  "severity": "medium",
  "description": "At least five failed admin logins from one source IP within ten minutes; indicates a brute-force pattern, not proof of compromise.",
  "srcip": "45.74.28.190",
  "dstip": "10.10.99.1",
  "username": "admin",
  "host": "FGT60FTK00000000",
  "eventtime": "1792745784383240000",
  "date": "2026-10-23",
  "time": "08:56:24",
  "tz": "+0530",
  "source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log",
  "line_number": 2160,
  "evidence": {
    "srcip": "45.74.28.190",
    "user": "admin",
    "status": "failed",
    "reason": "name_invalid",
    "msg": "Administrator admin login failed from https(45.74.28.190) because of invalid user name"
  },
  "matched_conditions": [
    {"field": "action", "op": "eq", "value": "login"},
    {"field": "status", "op": "eq", "value": "failed"},
    {"field": "user", "op": "eq", "value": "admin"},
    {
      "field": "aggregation",
      "op": "count_within",
      "value": {
        "key": "srcip",
        "threshold": 5,
        "window_seconds": 600,
        "observed_count": 5,
        "source_event_refs": [
          {"source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log", "line_number": 174},
          {"source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log", "line_number": 334},
          {"source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log", "line_number": 579},
          {"source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log", "line_number": 1714},
          {"source_file": "C:\\Users\\notyo\\OneDrive\\Desktop\\strc\\firex-10G.log", "line_number": 2160}
        ]
      }
    }
  ],
  "confidence": null,
  "mitre_techniques": ["T1110"]
}
```

**Errors:** `400 invalid_parameter`; `404 not_found`; `503 service_unavailable`; `500 internal_error`.

---

## 8. Techniques

**Method/path:** `GET /api/techniques`

**Parameters:** `limit` integer default `50`, range 1–200; `offset` integer default `0`, range 0–10,000; or opaque `cursor`, mutually exclusive with non-zero offset.

**Validation:** Reject invalid pagination values with `400 invalid_parameter`. The repository has technique IDs in each detection's serialized `mitre_techniques` JSON array, but no verified technique catalog/name/tactic file. Do not manufacture names.

**Data source/query:** Read and safely expand valid `mitre_techniques` JSON arrays from detections; aggregate distinct detection counts by exact ID; sort technique IDs ascending and paginate. The legacy 1,000-record sample contains one ID, `T1110`, on 147 detections. In the current full detector output, `T1110` is present on the 14,739 AUTH-001 aggregate detections; this is a rule-output count, not measured technique-label accuracy.

**Success — 200** (technique value/count are actual; pagination is proposed):

```json
{
  "items": [
    {
      "technique_id": "T1110",
      "detection_count": 147
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1,
    "next_cursor": null
  }
}
```

**Errors:** `400 invalid_parameter`; `503 service_unavailable`; `500 internal_error`.

## Common errors

All error responses use this proposed shape:

```json
{
  "error": {
    "code": "invalid_parameter",
    "message": "limit must be between 1 and 200",
    "details": {
      "parameter": "limit"
    },
    "request_id": "request-id-example"
  }
}
```

| HTTP status | Code | When |
|---:|---|---|
| 400 | `invalid_parameter` | Invalid UUID, enum, IP, eventtime, page, or mutually exclusive query parameter. |
| 404 | `not_found` | Incident or detection ID is valid but absent. |
| 413 | `graph_too_large` | Incident graph exceeds `max_nodes`; no partial graph is returned. |
| 413 | `response_too_large` | A JSON response exceeds the configured response-byte limit; the oversized success body is not returned. |
| 500 | `internal_error` | Unexpected query/serialization failure; response excludes SQL, paths, and stack traces. |
| 503 | `service_unavailable` | Required store is missing, unreadable, or temporarily unavailable. |
| 503 | `data_integrity_error` | A relationship references a missing detection or required graph node/edge. |
| 504 | `query_timeout` | A configured query deadline expired; cancellation and retry behavior must be explicit. |

## Open design questions

1. Confirm the `/api` prefix, response envelopes, and whether incident detail should page linked detections.
2. Confirm severity/status vocabulary and whether the planned service will expose status mutation (not included here).
3. Confirm whether eventtime query parameters should remain decimal nanoseconds; this proposal does not accept or normalize ISO timestamps.
4. Confirm operational limits (page sizes, graph depth/node cap, offset ceiling) against a real deployment.
5. Decide how the API receives a versioned, atomic manifest for the Parquet and graph snapshot.
6. Decide authentication, authorization, CORS, rate limiting, and whether evidence/source paths should be redacted. None is implemented or verified in the repository.
7. Decide whether technique names/tactics will be supplied by an authoritative MITRE catalog. The current Parquet only verifies IDs.

See [api-data-contracts.md](./api-data-contracts.md) for the JSON Schemas and stored-field mapping, and [api-performance-plan.md](./api-performance-plan.md) for query, connection, memory, and benchmark plans.
