content = r'''# API Data Contracts

Incident fields: incident_id string, title, description, severity, confidence, first_observed string, last_observed string, detection_count int, unique_source_events int, related_srcips string(JSON array), related_dstips string(JSON array), related_usernames, related_hosts, detection_ids string(JSON array), correlation_reasons string(JSON array), evidence_refs string(JSON array), status.

Detection fields: detection_id, rule_id, rule_name, category, severity, description, srcip, dstip, username, host, eventtime, date, time, tz, source_file, line_number int, evidence string(JSON object), matched_conditions string(JSON array), confidence, mitre_techniques string(JSON array).

Graph node: id string, type string, value string. Edge: source string, target string, rel string, evidence string or null, line int or null, observed bool.

Pagination: limit int, offset int, total int. Error: detail string. Nulls as JSON null.
'''
open("C:/Users/nsrn/Desktop/scaratch/docs/api-data-contracts.md","w").write(content)

content = r'''# API Performance Plan

DuckDB query: SELECT * FROM read_parquet(path) WHERE severity=? AND srcip=? ORDER BY eventtime LIMIT ? OFFSET ?.
Projection: SELECT needed columns.
Connection: open per request or pool; read-only.
Memory: bounded by batch/limit.
Pagination: default 50, max 200; large offset expensive; use keyset pagination if needed.
Benchmarks: 1K/1M/large; measure wall time and peak RSS. No results yet.
16GB constraints; 15/30/50GB risks: I/O and memory.
'''
open("C:/Users/nsrn/Desktop/scaratch/docs/api-performance-plan.md","w").write(content)
print("ok")
