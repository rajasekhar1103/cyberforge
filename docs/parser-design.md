# Parser Design

The Rust parser reads the source as bytes with a buffered `read_until('\n')` loop. It computes byte offsets from bytes consumed, strips LF or CRLF only from the record payload, and writes one Parquet row for every input record. Timestamp fields (`eventtime`, `date`, `time`, and `tz`) remain strings; no timestamp policy or numeric conversion is applied.

The key/value scanner handles quoted values and escapes. Malformed tokens, unterminated quotes, invalid UTF-8, and duplicate keys produce validation warnings. Malformed records are explicitly marked `quarantined`; their original bytes remain in `raw_record`. Duplicate keys remain last-wins in `fields_json`, and the duplicate warning is retained in `parse_warnings`.

The output preserves all fields as JSON text and the original record as a Parquet `Binary` value. Binary storage is required to preserve invalid UTF-8 without lossy conversion. `parse_warnings` is JSON-array text.

Arrow builders accumulate one configurable batch at a time (1,000 records by default; 25,000 maximum). Parquet row groups are capped at 64,000 rows, and ZSTD level 1 compression is enabled. Parsing uses two bounded workers by default; `--threads N` selects the worker count (use `--threads 1` for serial processing). Parallel parsing handles records within each input batch while preserving source order and byte offsets. Raw record batches are capped at 16 MiB plus at most one record, and unusually large retained buffers are released between batches. Peak memory still depends on the largest individual record, parsed-field expansion, and Parquet/compression buffers.

The 100 MiB development-sample comparison found two parsing workers faster than one with identical Parquet content and a small observed working-set difference. Full-size behavior and accuracy are not inferred from that sample. Use the VS Code task **Benchmark parser thread counts (100 MiB sample)** to rerun the comparison in an optimized release build. It alternates run order, checks all Parquet rows and columns for equality, and keeps benchmark outputs under the user's temporary directory.
