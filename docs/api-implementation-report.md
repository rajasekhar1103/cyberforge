# Phase 6B API Implementation Report

## Status

Implemented a FastAPI read-only investigation API backed by DuckDB. The service reads the configured analytics Parquet stores and node-link graph JSON. It does not modify parser, detection, correlation, graph-generation code, or analytics outputs. The implementation is validated against the existing 1,000-record sample artifacts; it is not production-ready and has not been benchmarked on large datasets.

## Endpoint status

| Endpoint | Status | Implementation notes |
|---|---|---|
| `GET /api/health` | Implemented | Readiness verifies that all four configured stores are present, readable, and have the expected top-level schemas. |
| `GET /api/summary` | Implemented | DuckDB totals and severity/category aggregates; validates relation references before returning. |
| `GET /api/incidents` | Implemented | Severity, source IP, username, and inclusive exact-numeric time filters; deterministic ordering; offset and generation-bound cursor pagination. |
| `GET /api/incidents/{incident_id}` | Implemented | Incident lookup plus authoritative relationship-table join, integrity checks, decoded JSON fields, and paginated detections. |
| `GET /api/incidents/{incident_id}/timeline` | Implemented | Compact projection ordered using DuckDB `HUGEINT`; timestamp strings are returned unchanged. |
| `GET /api/incidents/{incident_id}/graph` | Implemented | Bounded breadth-first traversal in DuckDB SQL; direction, filters, `observed`, seed nodes, endpoint integrity, and output limits are preserved/validated. No NetworkX graph is built. |
| `GET /api/detections/{detection_id}` | Implemented | Exact ID lookup with decoded JSON-text fields. |
| `GET /api/techniques` | Implemented | Validates and expands stored technique JSON; aggregates distinct detection counts and supports pagination. |

Errors use the documented envelope and include a request ID. Request validation maps to HTTP 400. Missing entities return 404; broken data relationships return 503; query deadlines return 504; graph or JSON response limits return 413. `response_too_large` was added to the common error schema and design table to represent the required JSON response-byte cap.

## Configuration and resource bounds

The default data directory is `data/analytics` relative to the process working directory. No temporary Kilo directory is hardcoded in application code. The directory can be overridden with `CYBERFORGE_DATA_DIR`; each store also has an individual path override.

| Setting | Default |
|---|---:|
| DuckDB memory limit | 256 MB |
| DuckDB threads | 2 |
| Concurrent/in-flight query slots | 1 |
| Query deadline | 30 seconds |
| Graph input size | 64 MiB |
| Graph response edges | 20,000 |
| JSON response body | 4 MiB |
| Incident-list page | 50; maximum 200 |
| Incident-detail detections page | 50; maximum 200 |
| Timeline page | 100; maximum 500 |
| Technique page | 50; maximum 200 |
| Graph depth / requested nodes | 1 / 1,000; maximum 3 / 5,000 |
| Offset | 0; maximum 10,000 |

DuckDB work runs on one dedicated worker thread and a single persistent connection, with bounded query slots and explicit timeout interruption. The async HTTP event loop does not execute blocking DuckDB queries. No unbounded Parquet result set or full NetworkX graph is materialized in Python. Configuration variables are defined in `api/config.py`; store paths are bound DuckDB parameters. There is no cache.

The response-byte middleware rejects oversized successful JSON bodies instead of truncating records. Database row/page caps and graph traversal limits also apply. DuckDB's configured memory limit is not a hard cap on total process RSS.

## Validation results

Command run:

```powershell
python -m unittest discover -s tests -p 'test_api.py' -v
```

Result: **10 tests passed**. The suite validates every endpoint's successful response against the Draft 2020-12 contracts in `api-data-contracts.md`, and validates common error bodies. It also exercises:

- Invalid UUIDs, filters, time ranges, pagination, graph parameters, and cursors.
- Missing incidents/detections and missing/unreadable required stores.
- Dangling incident/detection relationships and dangling graph endpoints.
- Exact eventtime ordering and unchanged timestamp strings from the sample.
- Graph depth, node/edge filters, derived-edge exclusion, and node limits.
- Oversized response handling and cursor continuation.

`python -m compileall -q api tests\test_api.py` also completed successfully. A live local Uvicorn process was started with the configured sample data directory, one worker, and port 8765; `GET /api/health` returned HTTP 200 with all four stores ready, and `/api/summary` returned 258 detections and 181 incidents. No existing analytics output was overwritten.

## Memory and performance observations

The previously verified development-host observation is **5.849 GiB total physical RAM and 0.615 GiB available** at the time of measurement. The 16 GiB figures in the performance plan remain a target design, not available hardware. The API defaults to a 256 MB DuckDB execution limit, two DuckDB threads, and one query slot; these are conservative configuration defaults, not measured safe production settings.

The inspected functional sample contains 258 detections, 181 incidents, 258 incident-detection relationships, and 786 graph nodes/1,326 edges. These tests establish functional behavior only. **No API throughput, peak-memory, 15 GB, 30 GB, or 50 GB benchmark was run.** No large-scale performance conclusion is supported.

## Known limitations and unresolved decisions

- The current sample files are under a temporary directory and are not an atomic, versioned dataset manifest. Cursor generation uses file path, size, and modification time; deploy immutable/versioned inputs before relying on snapshot consistency.
- Graph JSON is parsed by DuckDB for bounded traversal and is limited to 64 MiB by default. Larger graph stores should move to indexed node/edge Parquet artifacts or have a separately approved higher cap and measured memory budget.
- The API does not provide authentication, authorization, CORS policy, rate limiting, evidence-path redaction, or mutation endpoints. These remain decisions, not assumed policy.
- Counts and filters have not been performance-tested on production-size Parquet. DuckDB may spill to the configured temporary directory; available disk and spill behavior are unvalidated.
- The timeout interruption and concurrency controls have functional code coverage but have not been load-tested.
- There is no API load benchmark; the existing query benchmark plan is not an HTTP/API load test.

## Dashboard

A lightweight read-only Streamlit frontend is available in `dashboard/app.py`. It consumes the API rather than querying analytics files directly. Setup and start commands are documented in [dashboard-quickstart.md](./dashboard-quickstart.md). This UI has only been functionally exercised against the sample analytics and is not a production dashboard.

## Run commands (PowerShell)

From the project root, install API and test dependencies if needed:

```powershell
python -m pip install -r requirements-api-dev.txt
```

Run the API test suite against the existing sample:

```powershell
$env:CYBERFORGE_TEST_DATA_DIR = 'C:\Users\nsrn\AppData\Local\Temp\kilo'
python -m unittest discover -s tests -p 'test_api.py' -v
```

Start one API worker using the sample stores:

```powershell
$env:CYBERFORGE_DATA_DIR = 'C:\Users\nsrn\AppData\Local\Temp\kilo'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

Example readiness request from another PowerShell window:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/api/health' -Method Get
```
