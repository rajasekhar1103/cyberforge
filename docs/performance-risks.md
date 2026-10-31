# Performance Risks and Tier Choice

The parser already streams input and has a measured 6.54 GB run at 33.03 MB/s, with
1,109.9 MiB peak working set. The 100 MB prefix took 4.27 seconds in the recorded
benchmark and 4.61 seconds in a current repeat; projections use the slower repeat. The
detection engine projects only needed columns, indexes rules by event type, and buffers
Parquet writes. Correlation uses DuckDB's bounded-memory sort and disk spill.

On this laptop, the 100 MB end-to-end sample measured 4.61 seconds for parsing, a
4.58-second median for detection at batch size 5,000, and 2.49 seconds for correlation
at a 512 MB DuckDB limit. Linear projections from those measurements are:

| Tier | Parser | Detection | Correlation | Projected total |
|---|---:|---:|---:|---:|
| Core, 15 GB | 11.5 min | 11.5 min | 6.2 min | 29.2 min |
| Advanced, 30 GB | 23.1 min | 22.9 min | 12.5 min | 58.4 min |
| Extreme, 50 GB | 38.4 min | 38.2 min | 20.8 min | 97.3 min |

These are extrapolations, not tier benchmarks. They assume the same format, event and
detection rates, disk behavior, and no graph/API build time. Advanced is close to the
one-hour limit with little headroom; Core is the safer local choice. Do not select
Extreme on this laptop without running the actual tier and confirming the time limit.

The local 100 MB sample contains no planted-attack ground truth, so it cannot validate
detection recall, ATT&CK labels, attack-path order, or false-alarm rate. Do not trade
accuracy for speed or claim the accuracy gate from throughput tests alone.

Remaining scale risks:

- The parser must hold one full input record; the available full file contains a
  540,546,744-byte record.
- Correlation output preserves per-incident ID and evidence arrays, so an unusually
  large source-IP cluster can exceed the normal bounded-buffer memory profile.
- `graph-engine/graph.py` still builds the entire graph in NetworkX memory. It is not
  suitable for the 15/30/50 GB tiers until replaced with an out-of-core graph/index
  design. Tier projections above exclude graph construction and investigation queries.
