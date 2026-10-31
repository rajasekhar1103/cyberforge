# Parser Edge Cases

## Input characteristics observed

- Quoted values with spaces (for example `msg`, `ui`, `url`, and `logdesc`)
- Large numeric `eventtime` values
- Optional fields and unknown fields
- CRLF and LF line terminators
- Duplicate keys, escaped values, malformed tokens, invalid UTF-8, and an unterminated quoted value are covered by automated tests
- The full available input contains invalid UTF-8 and a 540,546,744-byte final record

## Current handling

- Quoted spaces are retained as one value.
- Escaped quotes and backslashes are decoded; unknown escape sequences retain their backslash.
- Duplicate keys are last-wins in `fields_json`; a duplicate-key warning is preserved in `parse_warnings`.
- Malformed tokens and unterminated quoted values are explicitly quarantined.
- Invalid UTF-8 is quarantined without lossy conversion; original bytes remain in `raw_record`.
- LF/CRLF byte offsets include the actual line terminator length.
- Large integers and timestamps are retained as strings.
- Unknown fields remain in `fields_json`.
