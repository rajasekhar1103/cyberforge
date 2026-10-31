# Parser Performance Benchmark

## Summary

The optimized release executable processed the complete available 6,543,120,032-byte input in 198.09 seconds. It wrote one output row per input record and completed without an error. This is a 6.54 GB benchmark, **not** a 50 GB benchmark.

The release parser improved throughput on the identical 500 MB prefix from 18.68 MB/s to 29.19 MB/s (+56.3%) in a same-session comparison. Peak working set decreased from 863.3 MiB to 39.5 MiB. A single 540,546,744-byte record in the full dataset raised the full-run peak to 1,109.9 MiB; memory is bounded across batches and row groups, but must still accommodate the largest individual record.

## Environment and method

- OS: Windows 11 Home Single Language, build 26300
- CPU: AMD Ryzen 5 5500U with Radeon Graphics, 12 logical processors
- Physical memory: 6,280,450,048 bytes (about 5.85 GiB)
- Rust build profiles: `cargo build` for debug; `cargo build --release` for release
- Input: `C:\Users\nsrn\Desktop\scaratch\firex-10G.log` (6,543,120,032 bytes; 13,752,384 line records, with no terminator on the final record)
- 100 MB and 500 MB samples are prefixes copied in binary mode through the first complete record at or above each threshold. Their exact sizes are 100,000,486 and 500,000,154 bytes.
- The timer measured process wall-clock time. Peak working set was sampled from the Windows process counter. Throughput uses decimal MB/GB; memory uses MiB.
- The old release executable was saved before modifying the parser. Baseline outputs are uncompressed Parquet; optimized outputs use ZSTD level 1. This is an end-to-end before/after comparison, not an isolated parser-only comparison.

## Debug versus release and before versus after

| Build | Input bytes | Input GB | Records | Time (s) | MB/s | GB/hour | Peak MiB | Parquet bytes | Parsed / quarantined |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Debug, before | 100,000,486 | 0.1000 | 189,415 | 22.06 | 4.53 | 16.3 | 233.7 | 226,457,915 | 189,415 / 0 |
| Debug, optimized | 100,000,486 | 0.1000 | 189,415 | 29.66 | 3.37 | 12.1 | 30.4 | 28,643,931 | 189,415 / 0 |
| Release, before | 100,000,486 | 0.1000 | 189,415 | 5.31 | 18.83 | 67.8 | 224.8 | 226,459,659 | 189,415 / 0 |
| Release, optimized | 100,000,486 | 0.1000 | 189,415 | 4.27 | 23.42 | 84.3 | 27.6 | 28,643,931 | 189,415 / 0 |
| Release, before | 500,000,154 | 0.5000 | 946,849 | 26.77 | 18.68 | 67.2 | 863.3 | 1,129,175,043 | 946,849 / 0 |
| Release, optimized | 500,000,154 | 0.5000 | 946,849 | 17.13 | 29.19 | 105.1 | 39.5 | 142,748,129 | 946,849 / 0 |

Debug timing did not improve: the optimized debug run was slower on the 100 MB sample, while substantially reducing memory and output size. The performance conclusions below are based on release builds.

## Release batch-size comparison

All runs used the identical 500,000,154-byte prefix and ZSTD level 1.

| Batch records | Input bytes | Input GB | Records | Time (s) | MB/s | GB/hour | Peak MiB | Parquet bytes | Parsed / quarantined |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 500,000,154 | 0.5000 | 946,849 | 16.99 | 29.43 | 105.9 | 34.7 | 142,748,129 | 946,849 / 0 |
| 5,000 | 500,000,154 | 0.5000 | 946,849 | 17.62 | 28.38 | 102.2 | 38.2 | 142,464,241 | 946,849 / 0 |
| 10,000 | 500,000,154 | 0.5000 | 946,849 | 19.94 | 25.08 | 90.3 | 46.0 | 142,591,776 | 946,849 / 0 |
| 25,000 | 500,000,154 | 0.5000 | 946,849 | 17.90 | 27.93 | 100.6 | 66.9 | 142,665,895 | 946,849 / 0 |

No larger batch improved throughput: 5,000 and 10,000 records were slower, while 25,000 was about 5% slower than 1,000 and used nearly twice the working set. The default remains 1,000 records. Batch sizes are accepted from 1 through 25,000 records; Parquet row groups are capped at 64,000 rows independently of the batch size.

## Complete available dataset

| Build | Input bytes | Input GB | Records | Time (s) | MB/s | GB/hour | Peak MiB | Parquet bytes | Parsed / quarantined |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Release, optimized, batch 1,000 | 6,543,120,032 | 6.5431 | 13,752,384 | 198.09 | 33.03 | 118.9 | 1,109.9 | 2,513,729,628 | 9,143,928 / 4,608,456 |

The full input contains a 540,546,744-byte final record and invalid UTF-8 beginning at record 9,125,383 (byte offset 4,815,675,394). The full run preserved each row's record bytes and marked malformed or invalid records as quarantined. The large final record materially affects compression and the measured throughput; the full-run rate should not be treated as representative of ordinary-sized records.

The pre-change full-file release run did not complete: it stopped on invalid UTF-8 at record 9,125,383 after 216.90 seconds, with a partial 9,889,829,004-byte Parquet output. It had processed approximately 4.82 GB and reported 9,100,000 parsed records in its last progress message. This was an input-handling failure, not a timeout.

## Projections (not benchmarks)

For projections, the 500 MB release rate with the default 1,000-record batch size (29.43 MB/s) is used instead of the full-run rate, which is skewed by the unusually large highly compressible record. These estimates assume the same hardware, data characteristics, and sustained throughput:

| Input size | Projected processing time |
|---:|---:|
| 15 GB | 8.49 minutes |
| 30 GB | 16.99 minutes |
| 50 GB | 28.31 minutes |

These are linear projections only. The 50 GB target has not been benchmarked.

## Optimizations measured

- Replaced per-column `Vec<String>` accumulation and per-flush vector transfers with Arrow builders, reducing per-record allocations and avoiding cloned batch vectors.
- Built the last-key-wins JSON map from borrowed field strings instead of cloning every key and value into a second owned map.
- Capped Parquet row groups at 64,000 rows; the previous Parquet default was 1,048,576 rows and caused memory to grow with the buffered row group.
- Enabled ZSTD level 1. On the identical 500 MB prefix, output decreased from 1,129,175,043 to 142,748,129 bytes (87.4% smaller), while release throughput increased.
- Avoided repeated copying of the source record into a `String`; the raw record is stored once in a Parquet binary column. Oversized line-buffer capacity is released after that record is appended.

## Commands and reproducibility

Build commands:

```powershell
Push-Location 'C:\Users\nsrn\Desktop\scaratch\cyberforge-parser'
cargo build
cargo build --release
cargo test
Pop-Location
```

Optimized full-input invocation:

```powershell
& 'C:\Users\nsrn\Desktop\scaratch\cyberforge-parser\target\release\cyberforge-parser.exe' `
  --input 'C:\Users\nsrn\Desktop\scaratch\firex-10G.log' `
  --output 'C:\Users\nsrn\.copilot\session-state\b7eb518c-cf69-45ea-8c00-26deafc74838\files\release-full-opt.parquet' `
  --batch-size 1000
```

The 500 MB batch runs used the same executable and prefix, with `--batch-size` set in turn to `1000`, `5000`, `10000`, and `25000`. The 100 MB debug/release runs used the same 100 MB prefix and `--batch-size 1000`. For each run, PowerShell `Start-Process` redirected stdout/stderr, `[Diagnostics.Stopwatch]` measured elapsed time, and the process working-set counter was polled until exit. Prefix samples were created by copying input in binary mode until each target byte threshold was reached, completing the current record before stopping.

The temporary prefixes can be recreated with this Python snippet (the script writes whole input records and may finish above each target):

```python
from pathlib import Path

source = Path(r"C:\Users\nsrn\Desktop\scaratch\firex-10G.log")
output_dir = Path(r"C:\Users\nsrn\.copilot\session-state\b7eb518c-cf69-45ea-8c00-26deafc74838\files")
targets = [100_000_000, 500_000_000]
outputs = [output_dir / "prefix-100mb.log", output_dir / "prefix-500mb.log"]
sizes = [0, 0]
output_dir.mkdir(parents=True, exist_ok=True)

with source.open("rb") as input_file, outputs[0].open("wb") as small, outputs[1].open("wb") as large:
    for record in input_file:
        for index, output in enumerate((small, large)):
            if sizes[index] < targets[index]:
                output.write(record)
                sizes[index] += len(record)

print(sizes)
```

The measured parser invocations used these executables and arguments; each run's output name matches the corresponding table row:

```powershell
$bench = 'C:\Users\nsrn\.copilot\session-state\b7eb518c-cf69-45ea-8c00-26deafc74838\files'
$input100 = Join-Path $bench 'prefix-100mb.log'
$input500 = Join-Path $bench 'prefix-500mb.log'
$debug = 'C:\Users\nsrn\Desktop\scaratch\cyberforge-parser\target\debug\cyberforge-parser.exe'
$release = 'C:\Users\nsrn\Desktop\scaratch\cyberforge-parser\target\release\cyberforge-parser.exe'
$baselineRelease = Join-Path $bench 'parser-before-optimization.exe'

& $debug --input $input100 --output (Join-Path $bench 'debug-100.parquet') --batch-size 1000
& $debug --input $input100 --output (Join-Path $bench 'debug-100-opt.parquet') --batch-size 1000
& $release --input $input100 --output (Join-Path $bench 'release-100-opt.parquet') --batch-size 1000
& $baselineRelease --input $input100 --output (Join-Path $bench 'release-100.parquet') --batch-size 1000
& $baselineRelease --input $input500 --output (Join-Path $bench 'release-500.parquet') --batch-size 1000
& $baselineRelease --input 'C:\Users\nsrn\Desktop\scaratch\firex-10G.log' --output (Join-Path $bench 'baseline-release-full.parquet') --batch-size 1000
foreach ($size in @(1000, 5000, 10000, 25000)) {
    & $release --input $input500 --output (Join-Path $bench "release-500-opt-$size.parquet") --batch-size $size
}
```

The first debug command was run before rebuilding `target\debug\cyberforge-parser.exe` from the optimized source. The baseline release executable was saved as `parser-before-optimization.exe` before the source changes.

Temporary benchmark files, including that saved baseline executable, were removed after collecting results. The sample-generation script and optimized full-run command above reproduce the current release benchmark; repeating the baseline requires rebuilding the pre-change parser and saving its release executable before building the optimized source.

## Limitations

- Only one machine and one full-input run were measured; no repeated-run variance or storage-device model was captured.
- The full dataset has unusual corruption and one 540 MB binary record. The high quarantine count and highly compressible tail may not match a clean production dataset.
- Memory is bounded by the configured batch and row-group sizes plus the largest single record and Parquet/compression buffers. A very large individual record can still require substantial working memory.
- The 15/30/50 GB values are projections, not measured completion times.
