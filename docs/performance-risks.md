# Performance Risks (50GB on 16GB RAM)

- Memory: avoid loading full file; stream in chunks; bound buffers.
- CPU: regex parsing hot path; use byte-level parser; parallel chunks.
- Disk I/O: sequential reads; batched writes; avoid random small writes.
- Concurrency: avoid data races; use channels/backpressure.
- Parquet: row group sizing; dictionary encoding; avoid too many small files.
- DuckDB: temp directory on fast disk; memory_limit; spill.
- Graph: NetworkX in-memory; sample/subgraph for large datasets; consider Neo4j if needed.
