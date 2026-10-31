# API Performance Plan

## Status and scope

This is a proposed plan for the planned FastAPI/DuckDB API. No API application, production connection pool, API benchmark, or 15/30/50 GB analytics dataset is present or verified. The DuckDB snippets below use current generated analytics output files and were syntax/execution-checked against the available sample. They are query patterns, not measured API performance. This document does not change parser, detection, correlation, graph, or pipeline code.

## Verified inputs and limits of current evidence

Readable generated data is under `C:\Users\nsrn\AppData\Local\Temp\kilo`:

| File | Actual rows/objects | Notes |
|---|---:|---|
| `detections.parquet` | 258 | Detection Parquet schema inspected. |
| `incidents.parquet` | 181 | Incident Parquet schema inspected. |
| `incident_detections.parquet` | 258 | Relationship table; sample validation reports all detections assigned. |
| `graph.json` | 786 nodes, 1,326 edges | NetworkX node-link JSON; 921 observed and 405 derived edges. |

These are outputs of the 1,000-record sample and are far too small to estimate production query performance. The root `out.parquet` could not be read because it lacks Parquet footer magic bytes. The earlier parser run measured a 6,543,120,032-byte raw-log input, not a valid large analytics Parquet set. No 15 GB, 30 GB, or 50 GB API/analytics query has been benchmarked.

Verified engine output schemas:

- Detections: strings for IDs, severity, entities, timestamps, evidence, matched conditions, and techniques; `line_number` is Int64. `evidence`, `matched_conditions`, and `mitre_techniques` contain JSON text.
- Incidents: IDs, severity/confidence/times, JSON-text entity arrays, detection IDs, reasons, evidence refs, and status; count fields are Int64.
- Relationships: `(incident_id, detection_id)`, both string IDs.
- Graph JSON: top-level `directed`, `multigraph`, `graph`, `nodes`, and `edges`.

**Development-machine memory verification (2026-11-01):** Windows reports `6,280,450,048` total physical bytes (5.849 GiB) on the AMD Ryzen 5 5500U machine. At the time of this check, `GlobalMemoryStatusEx` reported `660,824,064` bytes (0.615 GiB) currently available and 89% memory load. The earlier approximately 5.85 GiB observation was total recognized physical RAM, not currently available/free RAM. This machine is not a 16 GiB host. The 16 GiB budget below is a target design constraint, not installed hardware or a verified benchmark result; validation on a real 16 GiB host remains outstanding.

## DuckDB SQL patterns

Use `read_parquet(?)` with bound file paths and bind every request value separately. Do not interpolate a user string, path, UUID, filter, limit, or cursor into SQL. Cast `eventtime`/observation strings to `HUGEINT` only for comparisons and ordering; return their original text unchanged. `HUGEINT` is needed to avoid floating-point precision loss for 19-digit nanosecond strings.

The sample files used by the examples:

```text
detections = C:\Users\nsrn\AppData\Local\Temp\kilo\detections.parquet
incidents = C:\Users\nsrn\AppData\Local\Temp\kilo\incidents.parquet
relations = C:\Users\nsrn\AppData\Local\Temp\kilo\incident_detections.parquet
graph = C:\Users\nsrn\AppData\Local\Temp\kilo\graph.json
```

### Health

No table scan. Check process liveness plus the existence/openability of configured detections, incidents, `incident_detections.parquet`, and graph sources. All four stores are readiness dependencies; keep liveness independent of a potentially slow Parquet health query.

### Summary

Run bounded aggregate queries and combine their small result sets in the API. Example severity aggregate:

```sql
SELECT severity, count(*) AS n
FROM read_parquet(?)
GROUP BY severity
ORDER BY severity;
```

Totals and unassigned count:

```sql
SELECT
  (SELECT count(*) FROM read_parquet(?)) AS total_detections,
  (SELECT count(*) FROM read_parquet(?)) AS total_incidents,
  (SELECT count(*)
   FROM read_parquet(?) d
   WHERE NOT EXISTS (
     SELECT 1
     FROM read_parquet(?) r
     WHERE r.detection_id = d.detection_id
   )) AS unassigned_detections;
```

Use separate path parameters in the order each placeholder appears. Category aggregation uses the same `GROUP BY category` pattern. The sample reports 258 detections, 181 incidents, and zero unassigned detections.

### Incident list and exact count

Filters for `srcip`, `username`, `start_time`, and `end_time` apply to one common linked detection row. Severity applies to the incident row. This avoids combining an IP on one detection with a username/time on an unrelated detection.

```sql
WITH filtered AS (
  SELECT i.*
  FROM read_parquet(?) i
  WHERE (? IS NULL OR i.severity = ?)
    AND (
      (? IS NULL AND ? IS NULL AND ? IS NULL AND ? IS NULL)
      OR EXISTS (
        SELECT 1
        FROM read_parquet(?) r
        JOIN read_parquet(?) d USING (detection_id)
        WHERE r.incident_id = i.incident_id
          AND (? IS NULL OR d.srcip = ?)
          AND (? IS NULL OR d.username = ?)
          AND (? IS NULL OR TRY_CAST(d.eventtime AS HUGEINT) >= TRY_CAST(? AS HUGEINT))
          AND (? IS NULL OR TRY_CAST(d.eventtime AS HUGEINT) <= TRY_CAST(? AS HUGEINT))
      )
    )
)
SELECT *
FROM filtered
ORDER BY TRY_CAST(first_observed AS HUGEINT) DESC NULLS LAST, incident_id ASC
LIMIT ? OFFSET ?;
```

Run the same `WITH filtered AS (...) SELECT count(*) FROM filtered` for `pagination.total`. Bind limit/offset as checked integers; do not insert them into the SQL text. Avoid selecting `d.*` into the incident list. This pattern was exercised with the available sample files.

For cursor continuation, retain the exact last `(first_observed, incident_id)` pair in an opaque token and use:

```sql
AND (
  COALESCE(TRY_CAST(first_observed AS HUGEINT), -1) < TRY_CAST(? AS HUGEINT)
  OR (
    COALESCE(TRY_CAST(first_observed AS HUGEINT), -1) = TRY_CAST(? AS HUGEINT)
    AND incident_id > ?
  )
)
ORDER BY COALESCE(TRY_CAST(first_observed AS HUGEINT), -1) DESC, incident_id ASC
LIMIT ?;
```

The comparison matches descending time plus ascending ID order. Bind a cursor's decoded values; validate the cursor version and snapshot generation before using it.

### Incident detail and detection lookup

Fetch the incident separately by its exact ID:

```sql
SELECT *
FROM read_parquet(?)
WHERE incident_id = ?;
```

Fetch the relationship page with a join. This is the authoritative incident-to-detection mapping; do not use the incident's serialized `detection_ids` list as the join source:

```sql
SELECT d.*
FROM read_parquet(?) r
JOIN read_parquet(?) d USING (detection_id)
WHERE r.incident_id = ?
ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST, d.detection_id ASC
LIMIT ? OFFSET ?;
```

Count the relationship rows separately. For any relation whose detection row is missing, verify `count(*)` of the join equals the relation count; fail with a data-integrity error instead of silently omitting evidence.

### Detection detail

```sql
SELECT *
FROM read_parquet(?)
WHERE detection_id = ?;
```

The UUID parameter is bound. Expect zero or one row; a duplicate ID is a data-integrity failure.

### Timeline

The timeline is a projection of linked detections. The following is the incident join pattern without unneeded evidence JSON:

```sql
SELECT d.detection_id, d.eventtime, d.date, d.time, d.tz,
       d.rule_id, d.rule_name, d.severity, d.srcip, d.dstip,
       d.username, d.host, d.source_file, d.line_number
FROM read_parquet(?) r
JOIN read_parquet(?) d USING (detection_id)
WHERE r.incident_id = ?
ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST, d.detection_id ASC
LIMIT ? OFFSET ?;
```

Do not convert or rewrite the returned timestamp strings. Use the same relation count and page/cursor rules as incident detail.

### Techniques

`mitre_techniques` is JSON text. Validate JSON before expansion; malformed stored JSON should raise an observable data-integrity error, not be silently ignored. Use `CAST` rather than `TRY_CAST` here so malformed serialized values cannot quietly disappear from the aggregation. This pattern returns unique technique IDs and the number of detections containing each:

```sql
SELECT json_extract_string(j.value, '$') AS technique_id,
       count(DISTINCT d.detection_id) AS detection_count
FROM read_parquet(?) d
CROSS JOIN LATERAL json_each(CAST(d.mitre_techniques AS JSON)) j
GROUP BY technique_id
ORDER BY technique_id ASC
LIMIT ? OFFSET ?;
```

This syntax was executed against the sample; it returned `T1110` and 147. There is no verified technique-name catalog in the current repository.

### Incident graph filtering

Current graph input is the NetworkX node-link `graph.json`. DuckDB can expand its node and edge arrays and traverse only to a bounded depth. The recursive pattern below was executed against the sample and returned rows for a real incident. The request service applies `node_type` filters after traversal, retains the required incident/detection seed nodes, and enforces the node cap before serializing.

```sql
WITH RECURSIVE
seeds(node_id) AS (
  SELECT 'inc:' || ?
  UNION
  SELECT 'det:' || detection_id
  FROM read_parquet(?)
  WHERE incident_id = ?
),
raw_edges AS (
  SELECT
    json_extract_string(j.value, '$.source') AS source,
    json_extract_string(j.value, '$.target') AS target,
    json_extract_string(j.value, '$.rel') AS rel,
    TRY_CAST(json_extract(j.value, '$.observed') AS BOOLEAN) AS observed,
    j.value AS payload
  FROM read_json_auto(?) g
  CROSS JOIN LATERAL json_each(to_json(g.edges)) j
),
raw_nodes AS (
  SELECT
    json_extract_string(j.value, '$.id') AS id,
    json_extract_string(j.value, '$.type') AS type,
    j.value AS payload
  FROM read_json_auto(?) g
  CROSS JOIN LATERAL json_each(to_json(g.nodes)) j
),
walk(node_id, depth) AS (
  SELECT node_id, 0 FROM seeds
  UNION
  SELECT CASE WHEN e.source = w.node_id THEN e.target ELSE e.source END,
         w.depth + 1
  FROM walk w
  JOIN raw_edges e ON e.source = w.node_id OR e.target = w.node_id
  WHERE w.depth < ?
    AND (? OR e.observed)
),
selected AS (
  SELECT DISTINCT node_id FROM walk
)
SELECT 'node' AS record_kind, to_json(n.payload) AS payload
FROM selected s
JOIN raw_nodes n ON n.id = s.node_id
UNION ALL
SELECT 'edge' AS record_kind, to_json(e.payload) AS payload
FROM raw_edges e
WHERE e.source IN (SELECT node_id FROM selected)
  AND e.target IN (SELECT node_id FROM selected)
  AND (? OR e.observed);
```

Bind values in placeholder order: incident UUID, relationship path, incident UUID, graph path, graph path, depth (1–3), `include_derived`, `include_derived`. Apply requested relationship allow-list and node-type filters with bound values or in the result-processing step; never concatenate an allow-list into SQL. Validate that every edge endpoint is in the emitted node set. If selected nodes exceed the cap, return 413 rather than a partial or dangling graph.

Expanding a JSON graph reads the configured graph document, so it is suitable only while graph size is bounded. For larger graph artifacts, a proposed alternative is to publish indexed node/edge Parquet tables and run the same bounded traversal against those tables. That storage format is not present today.

## Connection lifecycle and concurrency

**Proposed initial deployment:**

1. Use one API worker process on a 16 GiB host; avoid multiplying DuckDB memory caps across web workers.
2. Maintain one DuckDB connection for read-only analytical queries. Serialize access with a bounded query semaphore/lock because a Python DuckDB connection should not be used concurrently by multiple request threads.
3. Keep FastAPI handlers async only for HTTP orchestration. Run blocking DuckDB work in a worker thread while holding the query slot; do not execute scans on the event loop.
4. Configure DuckDB `memory_limit='6GB'`, a dedicated fast `temp_directory`, and `threads=4` as starting targets. Verify these settings against the installed DuckDB release; they are proposed, not current configuration.
5. Apply an HTTP/query timeout and a bounded request queue. Return an explicit `503 service_unavailable` or `504 query_timeout` if a request cannot run within the agreed operational policy; do not create an unbounded queue.
6. Only add a second DuckDB connection/query slot after tests show headroom. If each connection gets a separate in-memory database, memory caps multiply; budget for the sum, not a presumed shared cap.
7. Prefer immutable, versioned Parquet inputs and a manifest identifying one complete dataset generation. Atomically switch the manifest after publishing all related files so requests do not combine detections, incidents, relations, and graph from different runs.

## Memory management, result bounds, and caching

For a 16 GiB machine, a conservative initial **budget proposal** is:

| Consumer | Target cap |
|---|---:|
| DuckDB execution and buffers | 6 GiB |
| API runtime, request handling, and serialization | 2 GiB |
| Optional graph cache | 1 GiB |
| OS, filesystem cache, and monitoring | 4 GiB |
| Unallocated safety headroom | 3 GiB |
| **Total** | **16 GiB** |

This is a planning allocation for a future 16 GiB host, not a measured or currently available memory budget on the development machine (5.849 GiB total; 0.615 GiB available at the measurement above). DuckDB's `memory_limit` is an execution/spill target, not a hard cap on all process RSS. If graph cache is disabled, leave the memory unused rather than raising DuckDB's limit without a load test. Require sufficient fast local disk for DuckDB spill, Parquet reads, and temporary outputs; set cleanup/quotas and alert before disk exhaustion.

- Set result limits before fetching rows. Avoid `fetchall()` for unbounded relations or full Parquet tables.
- Return only necessary columns. Decode JSON only for page rows, not every record in a scan.
- Cap detail/timeline pages and graph nodes/edges; set a response-byte budget as well as row limits because evidence strings can be large.
- Do not load detections, incidents, or the full 50 GB log into Python lists or a NetworkX object per request.
- Optional bounded cache: summary aggregates, distinct technique counts, and small graph adjacency. Use an LRU with a strict 1 GiB ceiling, maximum entry sizes, and cache keys that include the dataset-manifest generation and query parameters. Invalidate all entries on generation change. Never cache unbounded graph subgraphs.
- Cache only verified complete outputs. An absent, partial, corrupt, or mismatched manifest must fail health/readiness and API queries explicitly.
- Observe peak RSS/working set, DuckDB memory/spill, queue depth, query duration, output bytes, and source-file generation for each query family.

## Pagination and large offsets

- Proposed first-page defaults: incidents 50, linked detections/timeline 100, techniques 50. Enforce route-specific maximums from [api-design.md](./api-design.md).
- Offset pagination is acceptable for shallow pages; return a total count from a separate count query.
- Proposed maximum offset: 10,000. Reject larger offsets with `400 invalid_parameter` and direct clients to the cursor.
- Use deterministic ordering with a unique tie breaker. For incidents, order by exact numeric `first_observed` descending and `incident_id` ascending. For detections/timeline, order by exact numeric `eventtime` ascending and `detection_id` ascending.
- For deep traversal, use keyset pagination. The opaque cursor contains (or references server-side) the last ordering tuple plus a dataset-generation identifier. Validate it and bind decoded fields. Cursors from a different dataset generation must be rejected rather than silently skipping/duplicating rows.
- Never page a graph's nodes separately from its edges. Return a bounded complete subgraph or return `413 graph_too_large`; apply graph filters/depth before serialization.

## Reproducible PowerShell query benchmark

This benchmarks proposed DuckDB SQL against available Parquet/graph files; it is **not an HTTP/API load test**. It does not measure FastAPI routing, request parsing, JSON serialization, network latency, client concurrency, or HTTP queueing. Those require a future separate HTTP/API load test after route implementation, using representative clients, payloads, concurrency, and latency/error-rate measurements. The script records per-query repetitions and samples the Python process working set every 250 milliseconds; periodic sampling can miss short-lived memory spikes, so its reported peak is a sampled lower bound, not a guaranteed process peak. Use higher-resolution process/ETW telemetry for memory acceptance tests. Current paths exercise only the tiny generated sample (258 detections/181 incidents), so the output cannot be used to claim 15/30/50 GB performance.

Run from PowerShell with Python and the `duckdb` package already installed. No project dependency is changed:

```powershell
$data = 'C:\Users\nsrn\AppData\Local\Temp\kilo'
$script = Join-Path $env:TEMP 'cyberforge-api-query-bench.py'
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($script, @'
import argparse, json, os, time
import duckdb

p = argparse.ArgumentParser()
p.add_argument("--detections", required=True)
p.add_argument("--incidents", required=True)
p.add_argument("--relations", required=True)
p.add_argument("--graph", required=True)
p.add_argument("--incident-id", required=True)
p.add_argument("--detection-id", required=True)
p.add_argument("--repeat", type=int, default=5)
a = p.parse_args()
c = duckdb.connect(":memory:")
c.execute("SET memory_limit='6GB'")
c.execute("SET threads=4")
queries = [
    ("summary", "SELECT severity,count(*) FROM read_parquet(?) GROUP BY severity", [a.detections]),
    ("incident-list", "SELECT incident_id,severity,first_observed FROM read_parquet(?) ORDER BY TRY_CAST(first_observed AS HUGEINT) DESC NULLS LAST,incident_id LIMIT 50 OFFSET 0", [a.incidents]),
    ("incident-detail-lookup", "SELECT * FROM read_parquet(?) WHERE incident_id=?", [a.incidents,a.incident_id]),
    ("incident-detection-join", "SELECT d.detection_id,d.eventtime FROM read_parquet(?) r JOIN read_parquet(?) d USING(detection_id) WHERE r.incident_id=? ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST,d.detection_id", [a.relations,a.detections,a.incident_id]),
    ("detection-detail", "SELECT * FROM read_parquet(?) WHERE detection_id=?", [a.detections,a.detection_id]),
    ("timeline", "SELECT d.detection_id,d.eventtime,d.date,d.time,d.tz,d.rule_id,d.rule_name,d.severity,d.srcip,d.dstip,d.username,d.host,d.source_file,d.line_number FROM read_parquet(?) r JOIN read_parquet(?) d USING(detection_id) WHERE r.incident_id=? ORDER BY TRY_CAST(d.eventtime AS HUGEINT) ASC NULLS LAST,d.detection_id LIMIT 100 OFFSET 0", [a.relations,a.detections,a.incident_id]),
    ("techniques", "SELECT json_extract_string(j.value,'$'),count(DISTINCT d.detection_id) FROM read_parquet(?) d CROSS JOIN LATERAL json_each(CAST(d.mitre_techniques AS JSON)) j GROUP BY 1 ORDER BY 1", [a.detections]),
]
graph_sql = """WITH RECURSIVE
seeds(node_id) AS (
  SELECT 'inc:' || ?
  UNION
  SELECT 'det:' || detection_id FROM read_parquet(?) WHERE incident_id=?
),
edges AS (
  SELECT json_extract_string(j.value,'$.source') AS source,
         json_extract_string(j.value,'$.target') AS target,
         TRY_CAST(json_extract(j.value,'$.observed') AS BOOLEAN) AS observed
  FROM read_json_auto(?) g CROSS JOIN LATERAL json_each(to_json(g.edges)) j
),
walk(node_id,depth) AS (
  SELECT node_id,0 FROM seeds
  UNION
  SELECT CASE WHEN e.source=w.node_id THEN e.target ELSE e.source END,w.depth+1
  FROM walk w JOIN edges e ON e.source=w.node_id OR e.target=w.node_id
  WHERE w.depth < 1
),
selected AS (SELECT DISTINCT node_id FROM walk)
SELECT count(*) FROM (
  SELECT json_extract_string(j.value,'$.id') AS id
  FROM read_json_auto(?) g CROSS JOIN LATERAL json_each(to_json(g.nodes)) j
  JOIN selected s ON s.node_id=json_extract_string(j.value,'$.id')
)"""
queries.append(("incident-graph-depth-1", graph_sql, [a.incident_id,a.relations,a.incident_id,a.graph,a.graph]))
for name, sql, params in queries:
    for n in range(a.repeat):
        t=time.perf_counter()
        rows=c.execute(sql,params).fetchall()
        print(json.dumps({"query":name,"iteration":n+1,"seconds":round(time.perf_counter()-t,6),"rows":len(rows)}))
print(json.dumps({"input_bytes":{
    "detections":os.path.getsize(a.detections),
    "incidents":os.path.getsize(a.incidents),
    "relations":os.path.getsize(a.relations),
    "graph":os.path.getsize(a.graph)
}}))
'@, $utf8)

$args = @(
  '-u', "`"$script`"",
  '--detections', "`"$(Join-Path $data 'detections.parquet')`"",
  '--incidents', "`"$(Join-Path $data 'incidents.parquet')`"",
  '--relations', "`"$(Join-Path $data 'incident_detections.parquet')`"",
  '--graph', "`"$(Join-Path $data 'graph.json')`"",
  '--incident-id', '01e2b5d5-9688-4fd8-8d2d-4320f9b2a9a3',
  '--detection-id', 'f906e5df-a041-420d-bac1-63d840051506',
  '--repeat', '5'
) -join ' '
$p = Start-Process -FilePath (Get-Command python).Source -ArgumentList $args -PassThru -NoNewWindow
$timer = [Diagnostics.Stopwatch]::StartNew()
$peak = 0L
while (-not $p.HasExited) {
  $p.Refresh()
  if ($p.WorkingSet64 -gt $peak) { $peak = $p.WorkingSet64 }
  Start-Sleep -Milliseconds 250
}
$p.Refresh()
$timer.Stop()
"exit=$($p.ExitCode) wall_seconds=$([math]::Round($timer.Elapsed.TotalSeconds,2)) peak_working_set_MiB=$([math]::Round($peak/1MB,1))"
Remove-Item -LiteralPath $script
```

For an individual query plan, run the exact SQL with bound values through DuckDB's `EXPLAIN ANALYZE`; do not interpolate values into the SQL. Record DuckDB version (`python -c "import duckdb; print(duckdb.__version__)"`), hardware, dataset generation, file sizes, query parameters, warm/cold cache state, median and p95 over repeated runs, output row/byte count, peak working set, and spill bytes. Run the same script against all three approved data-size tiers when they exist. Record actual tier sizes rather than padding a dataset and representing it as real workload.

## 16 GiB and 15/30/50 GB validation plan

The 16 GiB budget above assumes one API process and bounded query concurrency. Large graph work and wide `SELECT *` scans are primary risks. The known parser run on this machine used less physical memory than 16 GiB and does not validate DuckDB/API behavior at that target.

| Analytics dataset tier | Validation risks | Required gates before approval |
|---:|---|---|
| 15 GB | Cold scan latency, OS page-cache competition, first spill, count-query cost, output JSON expansion. | Run each query family with representative selectivity and worst-case pages; repeat warm and cold; verify process+OS memory stays within 13 GiB (leaving 3 GiB headroom), no OOM, bounded spill, stable pagination and exact counts. |
| 30 GB | Spill throughput and temp-disk exhaustion; high concurrency; graph JSON expansion; large-offset regressions. | Repeat full workload with concurrent clients at the proposed queue limit; measure p50/p95/p99, peak RSS, spill and disk; verify cursor pages have no gaps/duplicates across a fixed manifest. |
| 50 GB | Sustained scan/spill throughput, long query timeouts, file count/partition pruning, graph growth and maintenance behavior. | Run the complete query matrix on a true 50 GB representative analytics snapshot on 16 GiB hardware; include restart/cold-cache tests, cancellation, disk-full handling, partial/corrupt manifest tests, and graph cap behavior. Do not infer this tier from linear extrapolation. |

For each tier, preserve a fixed dataset manifest and compare API results to direct DuckDB reference queries. Include empty filters, selective and unselective filters, missing IDs, null eventtimes, 19-digit eventtime boundaries, maximum page size, offset ceiling, cursor continuation, malformed stored JSON, dangling relations, graph cycles, derived-edge filtering, and graph node-cap boundaries. Confirm `eventtime` output strings are byte-for-byte unchanged. Load-test one query at a time first; only increase connections/workers when measured 16 GiB headroom remains.

## Risks and open questions

- No FastAPI routes or endpoint-level benchmark exist; sub-second/throughput SLAs must be measured after implementation.
- Current sample outputs are in a temporary directory, not a committed or versioned production manifest.
- Existing graph is a JSON object; expanding it per request does not scale to an unbounded 50 GB-derived graph.
- DuckDB's memory limit is not a total host memory cap; Arrow buffers, Python objects, OS cache, and concurrent connections also consume RAM.
- Broad count and summary queries may scan large files unless the deployment introduces immutable precomputed aggregates or suitable partitioning/indexing.
- Authentication, authorization, privacy/redaction, CORS, and request quotas are not present in the inspected app (no app exists).
- Confirm target DuckDB version, filesystem/partition layout, data refresh semantics, HTTP latency/error budgets, and actual 16 GiB hardware before treating any proposed limit as final.

Related contracts and route definitions: [api-data-contracts.md](./api-data-contracts.md) and [api-design.md](./api-design.md).
