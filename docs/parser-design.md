# Parser Design

The Rust parser reads the source as bytes with a buffered `read_until('\n')` loop. It computes byte offsets from bytes consumed, strips LF or CRLF only from the record payload, and writes one Parquet row for every input record. Timestamp fields (`eventtime`, `date`, `time`, and `tz`) remain strings; no timestamp policy or numeric conversion is applied.

The key/value scanner handles quoted values and escapes. Malformed tokens, unterminated quotes, invalid UTF-8, and duplicate keys produce validation warnings. Malformed records are explicitly marked `quarantined`; their original bytes remain in `raw_record`. Duplicate keys remain last-wins in `fields_json`, and the duplicate warning is retained in `parse_warnings`.

The output preserves all fields as JSON text and the original record as a Parquet `Binary` value. Binary storage is required to preserve invalid UTF-8 without lossy conversion. `parse_warnings` is JSON-array text.

Arrow builders accumulate one configurable batch at a time (1,000 records by default; 25,000 maximum). Parquet row groups are capped at 64,000 rows, and ZSTD level 1 compression is enabled. Memory use is bounded across batches and row groups, but still depends on the largest individual record and Parquet/compression buffers.
