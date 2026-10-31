# Correlation Benchmark

# Correlation Benchmark

## 100 MB parsed sample

- 48,275 detections processed into 5,586 incidents.
- DuckDB used two threads and a 512 MB memory limit with the configured temp directory.
- Elapsed wall time: 2.49 s; peak process working set: 171 MiB.
- A 128 MB DuckDB limit completed in 3.09 s with the same incident and relation counts.
- This sample does not force a large external spill; full-tier sort time remains unmeasured.

## Behavior parity

On the established 1,000-record sample, the streaming implementation produced 181
incidents and 258 detection relationships. The detection-to-incident partitions match
the previous implementation exactly; the largest incident contains 5 detections.

The timings are local sample measurements, not a Core/Advanced/Extreme benchmark. See
[performance-risks.md](../docs/performance-risks.md) for explicitly labeled tier
projections and the graph-stage limitation.
