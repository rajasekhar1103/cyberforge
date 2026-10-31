# Data Flow

1. Raw log file/stream chunked into bounded buffers (Rust).
2. Parser extracts key=value pairs, handling quotes and 48 distinct fields.
3. Normalizer maps to typed Arrow schema (eventtime ns, IPs, ports, etc.).
4. Writer appends to Parquet row groups, Zstd compressed, partitioned by date/type.
5. DuckDB queries Parquet directly (zero-copy where possible).
6. Detection engine evaluates YAML rules over DuckDB results.
7. MITRE mapper tags events with technique IDs.
8. Correlator groups into incidents.
9. Graph builder constructs attack path graph (NetworkX).
10. Reachability analyzer computes paths.
11. FastAPI serves JSON; React renders graph.
