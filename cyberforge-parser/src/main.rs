use anyhow::{bail, Result};
use arrow::array::builder::{BinaryBuilder, Int64Builder, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use clap::Parser as ClapParser;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::Arc;

const MAX_ROW_GROUP_SIZE: usize = 64_000;
const MAX_BATCH_SIZE: usize = 25_000;
const MAX_RETAINED_LINE_CAPACITY: usize = 1024 * 1024;

#[derive(ClapParser, Debug)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long)]
    output: String,
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ParseResult {
    fields: Vec<(String, String)>,
    warnings: Vec<String>,
    malformed: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct RunStats {
    lines: i64,
    parsed: i64,
    quarantined: i64,
}

struct Batch {
    source_file: StringBuilder,
    line_number: Int64Builder,
    byte_offset: Int64Builder,
    event_type: StringBuilder,
    subtype: StringBuilder,
    eventtime: StringBuilder,
    date: StringBuilder,
    time: StringBuilder,
    timezone: StringBuilder,
    raw_record: BinaryBuilder,
    fields_json: StringBuilder,
    parse_status: StringBuilder,
    parse_warnings: StringBuilder,
    rows: usize,
}

impl Batch {
    fn new() -> Self {
        Self {
            source_file: StringBuilder::new(),
            line_number: Int64Builder::new(),
            byte_offset: Int64Builder::new(),
            event_type: StringBuilder::new(),
            subtype: StringBuilder::new(),
            eventtime: StringBuilder::new(),
            date: StringBuilder::new(),
            time: StringBuilder::new(),
            timezone: StringBuilder::new(),
            raw_record: BinaryBuilder::new(),
            fields_json: StringBuilder::new(),
            parse_status: StringBuilder::new(),
            parse_warnings: StringBuilder::new(),
            rows: 0,
        }
    }

    fn append(
        &mut self,
        source_file: &str,
        line_number: i64,
        byte_offset: i64,
        fields: &BTreeMap<&str, &str>,
        raw_record: &[u8],
        fields_json: &str,
        parse_status: &str,
        parse_warnings: Option<&str>,
    ) {
        self.source_file.append_value(source_file);
        self.line_number.append_value(line_number);
        self.byte_offset.append_value(byte_offset);
        self.event_type.append_option(fields.get("type").copied());
        self.subtype.append_option(fields.get("subtype").copied());
        self.eventtime
            .append_option(fields.get("eventtime").copied());
        self.date.append_option(fields.get("date").copied());
        self.time.append_option(fields.get("time").copied());
        self.timezone.append_option(fields.get("tz").copied());
        self.raw_record.append_value(raw_record);
        self.fields_json.append_value(fields_json);
        self.parse_status.append_value(parse_status);
        self.parse_warnings.append_option(parse_warnings);
        self.rows += 1;
    }

    fn flush(&mut self, writer: &mut ArrowWriter<File>, schema: &Arc<Schema>) -> Result<()> {
        if self.rows == 0 {
            return Ok(());
        }

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(self.source_file.finish()),
                Arc::new(self.line_number.finish()),
                Arc::new(self.byte_offset.finish()),
                Arc::new(self.event_type.finish()),
                Arc::new(self.subtype.finish()),
                Arc::new(self.eventtime.finish()),
                Arc::new(self.date.finish()),
                Arc::new(self.time.finish()),
                Arc::new(self.timezone.finish()),
                Arc::new(self.raw_record.finish()),
                Arc::new(self.fields_json.finish()),
                Arc::new(self.parse_status.finish()),
                Arc::new(self.parse_warnings.finish()),
            ],
        )?;
        writer.write(&batch)?;
        self.rows = 0;
        Ok(())
    }
}

fn parse_kv(line: &[u8]) -> ParseResult {
    let mut fields = Vec::new();
    let mut warnings = Vec::new();
    let mut malformed = false;
    let bytes = line;
    let n = bytes.len();
    let mut i = 0;

    if let Err(error) = std::str::from_utf8(line) {
        warnings.push(format!(
            "invalid UTF-8 at byte offset {}",
            error.valid_up_to()
        ));
        malformed = true;
    }

    while i < n {
        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= n {
            break;
        }

        let key_start = i;
        while i < n && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i == key_start || i >= n || bytes[i] != b'=' {
            let token_len = bytes[key_start..]
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(n - key_start);
            warnings.push(format!(
                "malformed token at byte offset {key_start} ({token_len} bytes)"
            ));
            malformed = true;
            break;
        }

        let key = std::str::from_utf8(&bytes[key_start..i])
            .ok()
            .map(str::to_owned);
        i += 1;

        let value = if i < n && bytes[i] == b'"' {
            i += 1;
            let mut segment_start = i;
            let mut decoded = None::<Vec<u8>>;
            let mut closed = false;

            while i < n {
                if bytes[i] == b'"' {
                    if let Some(value) = decoded.as_mut() {
                        value.extend_from_slice(&bytes[segment_start..i]);
                    }
                    closed = true;
                    break;
                }

                if bytes[i] == b'\\' && i + 1 < n {
                    let value = decoded.get_or_insert_with(Vec::new);
                    value.extend_from_slice(&bytes[segment_start..i]);
                    match bytes[i + 1] {
                        b'n' => value.push(b'\n'),
                        b't' => value.push(b'\t'),
                        b'r' => value.push(b'\r'),
                        b'"' => value.push(b'"'),
                        b'\\' => value.push(b'\\'),
                        escaped => {
                            value.push(b'\\');
                            value.push(escaped);
                        }
                    }
                    i += 2;
                    segment_start = i;
                } else {
                    i += 1;
                }
            }

            if closed {
                let value = match decoded {
                    Some(value) => String::from_utf8(value).ok(),
                    None => std::str::from_utf8(&bytes[segment_start..i])
                        .ok()
                        .map(str::to_owned),
                };
                i += 1;
                value
            } else {
                warnings.push(format!(
                    "unterminated quoted value at byte offset {}",
                    key_start
                ));
                malformed = true;
                None
            }
        } else {
            let value_start = i;
            while i < n && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            std::str::from_utf8(&bytes[value_start..i])
                .ok()
                .map(str::to_owned)
        };

        if let (Some(key), Some(value)) = (key, value) {
            fields.push((key, value));
        }

        if i < n && !bytes[i].is_ascii_whitespace() {
            let token_len = bytes[i..]
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(n - i);
            warnings.push(format!(
                "malformed token at byte offset {i} ({token_len} bytes)"
            ));
            malformed = true;
            break;
        }
    }

    let mut seen = HashSet::new();
    for (key, _) in &fields {
        if !seen.insert(key.as_str()) {
            warnings.push(format!("duplicate key: {key}"));
        }
    }

    ParseResult {
        fields,
        warnings,
        malformed,
    }
}

fn strip_record_terminator(record: &mut Vec<u8>) {
    if record.last() == Some(&b'\n') {
        record.pop();
        if record.last() == Some(&b'\r') {
            record.pop();
        }
    }
}

fn run(args: Args) -> Result<RunStats> {
    if !(1..=MAX_BATCH_SIZE).contains(&args.batch_size) {
        bail!("--batch-size must be between 1 and {MAX_BATCH_SIZE}");
    }

    let total_size = std::fs::metadata(&args.input)?.len();
    let file = File::open(&args.input)?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let schema = Arc::new(Schema::new(vec![
        Field::new("source_file", DataType::Utf8, false),
        Field::new("line_number", DataType::Int64, false),
        Field::new("byte_offset", DataType::Int64, false),
        Field::new("type", DataType::Utf8, true),
        Field::new("subtype", DataType::Utf8, true),
        Field::new("eventtime", DataType::Utf8, true),
        Field::new("date", DataType::Utf8, true),
        Field::new("time", DataType::Utf8, true),
        Field::new("tz", DataType::Utf8, true),
        Field::new("raw_record", DataType::Binary, false),
        Field::new("fields_json", DataType::Utf8, false),
        Field::new("parse_status", DataType::Utf8, false),
        Field::new("parse_warnings", DataType::Utf8, true),
    ]));
    let out = File::create(&args.output)?;
    let props = WriterProperties::builder()
        .set_max_row_group_size(MAX_ROW_GROUP_SIZE)
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(1)?))
        .build();
    let mut writer = ArrowWriter::try_new(out, schema.clone(), Some(props))?;
    let mut batch = Batch::new();

    let mut line = Vec::new();
    let mut offset = 0_u64;
    let mut line_no = 0_i64;
    let mut parsed_records = 0_i64;
    let mut quarantined_records = 0_i64;

    loop {
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }

        line_no += 1;
        strip_record_terminator(&mut line);
        let result = parse_kv(&line);
        let fields: BTreeMap<&str, &str> = result
            .fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let fields_json = serde_json::to_string(&fields)?;
        let parse_status = if result.malformed {
            quarantined_records += 1;
            "quarantined"
        } else {
            parsed_records += 1;
            "parsed"
        };
        let warnings_json = if result.warnings.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&result.warnings)?)
        };

        batch.append(
            &args.input,
            line_no,
            i64::try_from(offset)?,
            &fields,
            &line,
            &fields_json,
            parse_status,
            warnings_json.as_deref(),
        );
        offset += u64::try_from(bytes_read)?;
        if line.capacity() > MAX_RETAINED_LINE_CAPACITY {
            line = Vec::new();
        } else {
            line.clear();
        }

        if batch.rows >= args.batch_size {
            batch.flush(&mut writer, &schema)?;
        }

        if line_no % 100_000 == 0 {
            let pct = (offset as f64 / total_size as f64) * 100.0;
            eprintln!(
                "processed {} lines, {} bytes ({:.2}%) parsed={} quarantined={}",
                line_no, offset, pct, parsed_records, quarantined_records
            );
        }
    }

    batch.flush(&mut writer, &schema)?;
    writer.close()?;

    Ok(RunStats {
        lines: line_no,
        parsed: parsed_records,
        quarantined: quarantined_records,
    })
}

fn main() -> Result<()> {
    let stats = run(Args::parse())?;
    println!(
        "done lines={} parsed={} quarantined={}",
        stats.lines, stats.parsed, stats.quarantined
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{BinaryArray, Int64Array, StringArray};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn parse_basic() {
        let result = parse_kv(br#"type=foo subtype="bar baz" eventtime=2024-01-01"#);
        assert!(!result.malformed);
        assert!(result.warnings.is_empty());
        assert_eq!(result.fields.len(), 3);
    }

    #[test]
    fn unterminated_quote_is_malformed() {
        let result = parse_kv(br#"x="unterminated"#);
        assert!(result.malformed);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("unterminated")));
    }

    #[test]
    fn duplicate_key_warning_is_retained() {
        let result = parse_kv(b"a=1 a=2");
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("duplicate key")));
    }

    #[test]
    fn malformed_token_is_reported() {
        for line in [b"a=1 trailing".as_slice(), b"a=\"1\"b=2".as_slice()] {
            let result = parse_kv(line);
            assert!(result.malformed);
            assert!(result
                .warnings
                .iter()
                .any(|warning| warning.contains("malformed token")));
        }
    }

    #[test]
    fn escaped_quotes_and_backslashes_are_decoded_without_losing_unknown_escapes() {
        let result = parse_kv(b"v=\"a\\\\b \\\"quoted\\\" \\q\"");
        assert_eq!(result.fields[0].1, "a\\b \"quoted\" \\q");
    }

    #[test]
    fn invalid_utf8_is_quarantined_without_lossy_conversion() {
        let result = parse_kv(b"value=bad\xffbytes");
        assert!(result.malformed);
        assert!(result
            .warnings
            .iter()
            .any(|warning| warning.contains("invalid UTF-8")));
        assert!(result.fields.is_empty());
    }

    #[test]
    fn large_integer_values_remain_strings() {
        let result = parse_kv(b"eventtime=18446744073709551615");
        assert_eq!(result.fields[0].1, "18446744073709551615");
    }

    #[test]
    fn batch_size_is_bounded() {
        for batch_size in [0, MAX_BATCH_SIZE + 1] {
            let error = run(Args {
                input: String::new(),
                output: String::new(),
                batch_size,
            })
            .unwrap_err();
            assert!(error.to_string().contains("--batch-size"));
        }
    }

    #[test]
    fn output_preserves_records_offsets_and_quarantine_warnings() {
        let directory = tempdir().unwrap();
        let input_path = directory.path().join("input.log");
        let output_path = directory.path().join("output.parquet");
        let records: [&[u8]; 6] = [
            b"type=foo eventtime=18446744073709551615\n",
            b"dup=1 dup=2\r\n",
            b"x=\"unfinished\n",
            b"bad=\xff\n",
            b"good=1 trailing\n",
            b"escaped=\"a\\\\b \\\"q\\\"\"",
        ];
        let mut input = File::create(&input_path).unwrap();
        let mut offsets = Vec::new();
        let mut offset = 0_i64;
        for record in records {
            offsets.push(offset);
            input.write_all(record).unwrap();
            offset += record.len() as i64;
        }
        drop(input);

        let stats = run(Args {
            input: input_path.to_string_lossy().into_owned(),
            output: output_path.to_string_lossy().into_owned(),
            batch_size: 2,
        })
        .unwrap();
        assert_eq!(
            stats,
            RunStats {
                lines: 6,
                parsed: 3,
                quarantined: 3
            }
        );

        let file = File::open(output_path).unwrap();
        let mut reader = ParquetRecordBatchReaderBuilder::try_new(file)
            .unwrap()
            .build()
            .unwrap();
        let batch = reader.next().unwrap().unwrap();
        assert_eq!(batch.num_rows(), records.len());
        let offsets_array = batch
            .column(2)
            .as_any()
            .downcast_ref::<Int64Array>()
            .unwrap();
        let raw_records = batch
            .column(9)
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap();
        let fields_json = batch
            .column(10)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let statuses = batch
            .column(11)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();
        let warnings = batch
            .column(12)
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap();

        for (index, expected) in offsets.iter().enumerate() {
            assert_eq!(offsets_array.value(index), *expected);
        }
        assert_eq!(raw_records.value(1), b"dup=1 dup=2");
        assert_eq!(raw_records.value(3), b"bad=\xff");
        assert_eq!(raw_records.value(5), records[5]);
        assert_eq!(statuses.value(1), "parsed");
        assert_eq!(statuses.value(2), "quarantined");
        assert_eq!(statuses.value(3), "quarantined");
        assert_eq!(statuses.value(4), "quarantined");
        assert!(warnings.value(1).contains("duplicate key"));
        assert!(warnings.value(2).contains("unterminated quoted value"));
        assert!(warnings.value(3).contains("invalid UTF-8"));
        assert!(warnings.value(4).contains("malformed token"));
        assert_eq!(
            serde_json::from_str::<BTreeMap<String, String>>(fields_json.value(0))
                .unwrap()
                .get("eventtime")
                .unwrap(),
            "18446744073709551615"
        );
    }
}
