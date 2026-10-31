# Parser Validation

## Full available input

- Input: `firex-10G.log`, 6,543,120,032 bytes
- Input records: 13,752,384
- Output rows: 13,752,384
- Parsed: 9,143,928
- Quarantined: 4,608,456
- Parquet output: 2,513,729,628 bytes
- Completion: successful release run; every record was written as parsed or quarantined

Quarantined records retain their original bytes in the Parquet `raw_record` binary column. The `parse_warnings` column contains a JSON array, including malformed-token, unterminated-quote, invalid-UTF-8, and duplicate-key warnings. Duplicate keys remain last-wins in `fields_json`, with the duplicate warning retained.

## Preservation checks

- `eventtime`, `date`, `time`, `tz`, and all other parsed field values remain strings; no integer or timestamp conversion is applied.
- A large integer value is covered by an automated exact-string test.
- LF and CRLF offsets are checked in an output Parquet integration test; offsets count original input bytes, including line terminators.
- Invalid UTF-8 is never passed through lossy decoding. Such rows are quarantined and their raw bytes round-trip through the binary Parquet column.
- Escaped quotes, escaped backslashes, and unknown escapes have automated tests.
- Unterminated quoted values and malformed tokens are quarantined with warnings.

## Automated tests

`cargo test` — 9 tests passed, including an end-to-end Parquet read-back test that verifies byte offsets, raw bytes, exact large integer text, duplicate warnings, and quarantine status.

## Schema and compatibility note

`raw_record` is now Parquet `Binary` rather than `Utf8` so invalid source bytes can be preserved exactly. `parse_warnings` is JSON-array text rather than a semicolon-joined warning string. Consumers should account for those representation changes.
