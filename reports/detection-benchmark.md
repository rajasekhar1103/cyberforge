# Detection Benchmark

## 100 MB parsed sample

- Input: 189,415 rows from the same 100,000,486-byte log prefix used by the parser
  benchmark.
- Output: 48,275 detections (2.73 MiB), unchanged across tested input batch sizes.
- Runs used Python 3.14.8, PyArrow, and the laptop's Ryzen 5 5500U.

| Input batch rows | Run 1 | Run 2 | Median* | Peak working set |
|---:|---:|---:|---:|---:|
| 1,000 | 4.73 s | 4.87 s | 4.80 s | 143 MiB |
| 5,000 | 4.52 s | 4.64 s | 4.58 s | 171 MiB |
| 10,000 | 4.72 s | 4.84 s | 4.78 s | 218 MiB |

*For two runs, median is the midpoint of the two measurements.

Batch size 5,000 was the fastest measured option with moderate memory use; it remains
the default. These timings include interpreter startup and file output and are not a
full-tier benchmark. The parser repeated the same prefix at 4.61 seconds in the current
session (4.27 seconds in the recorded parser report), so tier calculations use 4.61
seconds as a conservative parser rate. The 1,000-record development sample still
produces the validated
baseline of 258 detections, including 147 AUTH-001, 44 NET-001, 27 IPS-001, 21 IPS-002,
13 AV-001, and 6 WEB-001 matches.

## Full available log

The optimized parser output for the full `firex-10G.log` was processed with input batch
size 5,000 on the Ryzen 5 5500U laptop:

| Parsed rows | Parsed Parquet | Time | Rows/second | Parquet MB/s | Peak working set | Detections | Output Parquet |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 13,752,384 | 2.514 GB | 166.41 s | 82,643 | 15.11 | 399 MiB | 2,322,055 | 0.127 GB |

This is the actual full-file detection-stage timing; it supersedes linear estimates
from the 100 MB sample for this dataset. Detection output was verified to contain
2,322,055 rows in 567 row groups. The output is stored alongside the parsed Parquet
under the Windows temporary directory.
