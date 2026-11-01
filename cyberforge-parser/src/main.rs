use anyhow::{bail, Result};
use arrow::array::builder::{BinaryBuilder, Int64Builder, StringBuilder};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use clap::Parser as ClapParser;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use rayon::prelude::*;
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_ROW_GROUP_SIZE: usize = 64_000;
const MAX_BATCH_SIZE: usize = 25_000;
const MAX_RETAINED_LINE_CAPACITY: usize = 1024 * 1024;
const MAX_RAW_BATCH_BYTES: usize = 16 * 1024 * 1024;
const TIMESTAMP_SCAN_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const TIMESTAMP_PATTERN_SIZE: usize = 29;

#[derive(ClapParser, Debug)]
struct Args {
    #[arg(short, long)]
    input: String,
    #[arg(short, long, required_unless_present = "scan_timestamps")]
    output: Option<String>,
    #[arg(
        long,
        help = "Scan timestamps only, without parsing or writing Parquet"
    )]
    scan_timestamps: bool,
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,
    #[arg(
        long,
        default_value_t = 2,
        help = "Parsing worker threads; defaults to two bounded workers"
    )]
    threads: usize,
}

struct RawRecord {
    start: usize,
    end: usize,
    offset: u64,
    line_no: i64,
}

struct ParsedRecord {
    fields: BTreeMap<String, String>,
    fields_json: String,
    warnings_json: Option<String>,
    malformed: bool,
    offset: i64,
    line_no: i64,
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

struct TimestampScanStats {
    count: u64,
    first: Option<[u8; TIMESTAMP_PATTERN_SIZE]>,
    last: Option<[u8; TIMESTAMP_PATTERN_SIZE]>,
    elapsed: Duration,
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

fn parse_record(bytes: &[u8], record: &RawRecord) -> Result<ParsedRecord> {
    let result = parse_kv(&bytes[record.start..record.end]);
    let fields: BTreeMap<String, String> = result.fields.into_iter().collect();
    let fields_json = serde_json::to_string(&fields)?;
    let warnings_json = if result.warnings.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&result.warnings)?)
    };

    Ok(ParsedRecord {
        fields,
        fields_json,
        warnings_json,
        malformed: result.malformed,
        offset: i64::try_from(record.offset)?,
        line_no: record.line_no,
    })
}

fn is_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

fn timestamp_at(bytes: &[u8], index: usize) -> bool {
    let timestamp = &bytes[index..index + TIMESTAMP_PATTERN_SIZE];
    if !timestamp.starts_with(b"date=")
        || timestamp[9] != b'-'
        || timestamp[12] != b'-'
        || timestamp[15] != b' '
        || &timestamp[16..21] != b"time="
        || timestamp[23] != b':'
        || timestamp[26] != b':'
        || ![5, 6, 7, 8, 10, 11, 13, 14, 21, 22, 24, 25, 27, 28]
            .iter()
            .all(|position| is_digit(timestamp[*position]))
    {
        return false;
    }

    let number = |start: usize, length: usize| {
        timestamp[start..start + length]
            .iter()
            .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
    };
    let year = number(5, 4);
    let month = number(10, 2);
    let day = number(13, 2);
    let hour = number(21, 2);
    let minute = number(24, 2);
    let second = number(27, 2);
    if !(1..=12).contains(&month) || !(0..=23).contains(&hour) || minute > 59 || second > 59 {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=days_in_month).contains(&day)
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

fn timestamp_epoch_seconds(timestamp: &[u8; TIMESTAMP_PATTERN_SIZE]) -> u64 {
    let number = |start: usize, length: usize| {
        timestamp[start..start + length]
            .iter()
            .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
    };
    let year = number(5, 4);
    let month = number(10, 2);
    let day = number(13, 2);
    let hour = number(21, 2);
    let minute = number(24, 2);
    let second = number(27, 2);
    let days_before_year =
        |year: u64| 365 * year + (year + 3) / 4 - (year + 99) / 100 + (year + 399) / 400;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_lengths = [
        31_u64,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let days_in_prior_months: u64 = month_lengths[..month as usize - 1].iter().sum();
    let days = days_before_year(year) + days_in_prior_months + day - 1;
    days * 86_400 + hour * 3_600 + minute * 60 + second
}

fn scan_timestamps(path: &str) -> Result<TimestampScanStats> {
    let total_size = std::fs::metadata(path)?.len();
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; TIMESTAMP_SCAN_BUFFER_SIZE + TIMESTAMP_PATTERN_SIZE - 1];
    let mut carry = 0;
    let mut count = 0_u64;
    let mut first: Option<[u8; TIMESTAMP_PATTERN_SIZE]> = None;
    let mut last: Option<[u8; TIMESTAMP_PATTERN_SIZE]> = None;
    let mut bytes_scanned = 0_u64;
    let start = Instant::now();
    let mut last_progress = start;

    loop {
        let bytes_read = file.read(&mut buffer[carry..carry + TIMESTAMP_SCAN_BUFFER_SIZE])?;
        if bytes_read == 0 {
            break;
        }

        let available = carry + bytes_read;
        let scan_end = available.saturating_sub(TIMESTAMP_PATTERN_SIZE - 1);
        for index in 0..scan_end {
            if buffer[index] != b'd' || !timestamp_at(&buffer, index) {
                continue;
            }

            let mut timestamp = [0_u8; TIMESTAMP_PATTERN_SIZE];
            timestamp.copy_from_slice(&buffer[index..index + TIMESTAMP_PATTERN_SIZE]);
            if first.as_ref().map_or(true, |value| timestamp < *value) {
                first = Some(timestamp);
            }
            if last.as_ref().map_or(true, |value| timestamp > *value) {
                last = Some(timestamp);
            }
            count += 1;
        }

        carry = available - scan_end;
        buffer.copy_within(scan_end..available, 0);
        bytes_scanned += bytes_read as u64;

        if last_progress.elapsed() >= Duration::from_millis(500) {
            let elapsed = start.elapsed().as_secs_f64();
            let mb_per_second = bytes_scanned as f64 / (1024.0 * 1024.0) / elapsed;
            let fraction = if total_size == 0 {
                1.0
            } else {
                bytes_scanned as f64 / total_size as f64
            };
            let eta = if mb_per_second > 0.0 {
                Duration::from_secs_f64(
                    (total_size.saturating_sub(bytes_scanned) as f64 / (1024.0 * 1024.0))
                        / mb_per_second,
                )
            } else {
                Duration::ZERO
            };
            eprint!(
                "\rScanning timestamps: {:5.1}% | {:.1} MB/s | ETA {}",
                fraction * 100.0,
                mb_per_second,
                format_duration(eta)
            );
            std::io::stderr().flush()?;
            last_progress = Instant::now();
        }
    }

    let elapsed = start.elapsed();
    if total_size > 0 {
        let mb_per_second =
            bytes_scanned as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64().max(0.001);
        eprint!(
            "\rScanning timestamps: 100.0% | {:.1} MB/s | ETA 00:00:00\n",
            mb_per_second
        );
        std::io::stderr().flush()?;
    }

    Ok(TimestampScanStats {
        count,
        first,
        last,
        elapsed,
    })
}

fn print_timestamp_scan(stats: TimestampScanStats) {
    println!("Timestamped records: {}", stats.count);
    match (stats.first, stats.last) {
        (Some(first), Some(last)) => {
            let first_text = String::from_utf8_lossy(&first);
            let last_text = String::from_utf8_lossy(&last);
            let first_value = &first_text[5..];
            let last_value = &last_text[5..];
            let span_seconds = timestamp_epoch_seconds(&last) - timestamp_epoch_seconds(&first);
            println!("Earliest timestamp:  {first_value}");
            println!("Latest timestamp:    {last_value}");
            println!(
                "Log time span:       {} days, {:02}:{:02}:{:02}",
                span_seconds / 86_400,
                (span_seconds / 3_600) % 24,
                (span_seconds / 60) % 60,
                span_seconds % 60
            );
        }
        _ => println!("No timestamps found."),
    }
    println!("Scan runtime:        {}", format_duration(stats.elapsed));
}

fn run(args: Args) -> Result<RunStats> {
    if !(1..=MAX_BATCH_SIZE).contains(&args.batch_size) {
        bail!("--batch-size must be between 1 and {MAX_BATCH_SIZE}");
    }
    if args.threads == 0 {
        bail!("--threads must be greater than zero");
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
    let output_path = args
        .output
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--output is required unless --scan-timestamps is used"))?;
    let out = File::create(output_path)?;
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
    let mut raw_bytes = Vec::new();
    let mut records = Vec::with_capacity(args.batch_size);
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build()?;

    loop {
        while records.len() < args.batch_size && raw_bytes.len() < MAX_RAW_BATCH_BYTES {
            let bytes_read = reader.read_until(b'\n', &mut line)?;
            if bytes_read == 0 {
                break;
            }

            line_no += 1;
            strip_record_terminator(&mut line);
            let start = raw_bytes.len();
            raw_bytes.extend_from_slice(&line);
            records.push(RawRecord {
                start,
                end: raw_bytes.len(),
                offset,
                line_no,
            });
            offset += u64::try_from(bytes_read)?;

            if line.capacity() > MAX_RETAINED_LINE_CAPACITY {
                line = Vec::new();
            } else {
                line.clear();
            }
        }

        if records.is_empty() {
            break;
        }

        let parsed = if args.threads == 1 {
            records
                .iter()
                .map(|record| parse_record(&raw_bytes, record))
                .collect::<Result<Vec<_>>>()?
        } else {
            thread_pool.install(|| {
                records
                    .par_iter()
                    .map(|record| parse_record(&raw_bytes, record))
                    .collect::<Result<Vec<_>>>()
            })?
        };

        for (record, parsed) in records.iter().zip(parsed) {
            let fields: BTreeMap<&str, &str> = parsed
                .fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect();
            let parse_status = if parsed.malformed {
                quarantined_records += 1;
                "quarantined"
            } else {
                parsed_records += 1;
                "parsed"
            };

            batch.append(
                &args.input,
                parsed.line_no,
                parsed.offset,
                &fields,
                &raw_bytes[record.start..record.end],
                &parsed.fields_json,
                parse_status,
                parsed.warnings_json.as_deref(),
            );
        }
        batch.flush(&mut writer, &schema)?;
        writer.flush()?;

        if line_no % 100_000 == 0 {
            let pct = (offset as f64 / total_size as f64) * 100.0;
            eprintln!(
                "processed {} lines, {} bytes ({:.2}%) parsed={} quarantined={}",
                line_no, offset, pct, parsed_records, quarantined_records
            );
        }

        records.clear();
        if raw_bytes.capacity() >= MAX_RAW_BATCH_BYTES * 2 {
            raw_bytes = Vec::new();
        } else {
            raw_bytes.clear();
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
    let args = Args::parse();
    if args.scan_timestamps {
        print_timestamp_scan(scan_timestamps(&args.input)?);
        return Ok(());
    }

    let stats = run(args)?;
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
    fn timestamp_scan_handles_binary_bytes_and_reports_the_full_range() {
        let directory = tempdir().unwrap();
        let input_path = directory.path().join("input.log");
        std::fs::write(
            &input_path,
            b"date=2026-10-23 time=08:48:26 type=traffic\n\
              date=2026-02-30 time=12:00:00 invalid=date\n\
              date=2026-10-30 time=08:48:25 \xff\xfe",
        )
        .unwrap();

        let stats = scan_timestamps(input_path.to_str().unwrap()).unwrap();

        assert_eq!(stats.count, 2);
        assert_eq!(stats.first.unwrap(), *b"date=2026-10-23 time=08:48:26");
        assert_eq!(stats.last.unwrap(), *b"date=2026-10-30 time=08:48:25");
        assert_eq!(
            timestamp_epoch_seconds(&stats.last.unwrap())
                - timestamp_epoch_seconds(&stats.first.unwrap()),
            604_799
        );
    }

    #[test]
    fn batch_size_is_bounded() {
        for batch_size in [0, MAX_BATCH_SIZE + 1] {
            let error = run(Args {
                input: String::new(),
                output: None,
                scan_timestamps: false,
                batch_size,
                threads: 1,
            })
            .unwrap_err();
            assert!(error.to_string().contains("--batch-size"));
        }
    }

    #[test]
    fn thread_count_must_be_positive() {
        let error = run(Args {
            input: String::new(),
            output: None,
            scan_timestamps: false,
            batch_size: 1,
            threads: 0,
        })
        .unwrap_err();
        assert!(error.to_string().contains("--threads"));
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
            output: Some(output_path.to_string_lossy().into_owned()),
            scan_timestamps: false,
            batch_size: 2,
            threads: 1,
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

    #[test]
    fn parallel_parsing_preserves_order_and_output() {
        let directory = tempdir().unwrap();
        let input_path = directory.path().join("input.log");
        let sequential_path = directory.path().join("sequential.parquet");
        let parallel_path = directory.path().join("parallel.parquet");
        let records: [&[u8]; 6] = [
            b"type=foo eventtime=18446744073709551615\n",
            b"dup=1 dup=2\r\n",
            b"x=\"unfinished\n",
            b"bad=\xff\n",
            b"good=1 trailing\n",
            b"escaped=\"a\\\\b \\\"q\\\"\"",
        ];
        let mut input = File::create(&input_path).unwrap();
        for record in records {
            input.write_all(record).unwrap();
        }
        drop(input);

        for (output_path, threads) in [(&sequential_path, 1), (&parallel_path, 2)] {
            let stats = run(Args {
                input: input_path.to_string_lossy().into_owned(),
                output: Some(output_path.to_string_lossy().into_owned()),
                scan_timestamps: false,
                batch_size: 2,
                threads,
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
        }

        let read_batches = |path: &std::path::Path| {
            ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
                .unwrap()
                .with_batch_size(2)
                .build()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        };
        let sequential = read_batches(&sequential_path);
        let parallel = read_batches(&parallel_path);
        assert_eq!(sequential.len(), parallel.len());
        for (sequential_batch, parallel_batch) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(sequential_batch.num_rows(), parallel_batch.num_rows());
            for (sequential_column, parallel_column) in sequential_batch
                .columns()
                .iter()
                .zip(parallel_batch.columns())
            {
                assert_eq!(sequential_column.to_data(), parallel_column.to_data());
            }
        }
    }

    #[test]
    fn raw_record_batches_are_bounded_by_bytes_and_keep_rows() {
        let directory = tempdir().unwrap();
        let input_path = directory.path().join("input.log");
        let output_path = directory.path().join("output.parquet");
        let large_record = format!("value={}\n", "x".repeat(MAX_RAW_BATCH_BYTES));
        std::fs::write(&input_path, format!("{large_record}value=last")).unwrap();

        let stats = run(Args {
            input: input_path.to_string_lossy().into_owned(),
            output: Some(output_path.to_string_lossy().into_owned()),
            scan_timestamps: false,
            batch_size: 100,
            threads: 2,
        })
        .unwrap();
        assert_eq!(
            stats,
            RunStats {
                lines: 2,
                parsed: 2,
                quarantined: 0
            }
        );

        let builder =
            ParquetRecordBatchReaderBuilder::try_new(File::open(output_path).unwrap()).unwrap();
        assert_eq!(builder.metadata().num_row_groups(), 2);
        assert_eq!(builder.metadata().num_row_groups(), 2);
        let reader = builder.build().unwrap();
        let rows = reader.map(|batch| batch.unwrap().num_rows()).sum::<usize>();
        assert_eq!(rows, 2);
    }
}
