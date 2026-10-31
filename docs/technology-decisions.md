# Technology Decisions

- Rust for parsing/ingestion: zero-copy, memory-safe, streaming.
- Arrow/Parquet: columnar, interoperable with DuckDB/Python.
- Zstd: high compression ratio for logs.
- DuckDB: embedded OLAP, reads Parquet, spills to disk.
- Python for detection/correlation: ecosystem (YAML, NetworkX).
- YAML rules: configurable, auditable detections.
- MITRE ATT&CK: standard technique taxonomy.
- NetworkX: graph algorithms for attack paths.
- FastAPI: async API.
- React + Cytoscape.js: interactive graph visualization.
