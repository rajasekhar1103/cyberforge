# Phase 3B — Detection Optimization Benchmark

## Summary

On the identical 100,000-row sample and rules, the optimized detector was **10.98x
faster** by median wall time, used about **83% less peak working set** in the repeated
measurements, and emitted semantically equivalent detections. Buffered Parquet output
was about **98.9% smaller** than the baseline output because it avoided a row group
for every detection.

These are sample measurements, not projections or production-scale results.

## Benchmark setup

- **Input:** 100,000 parsed Parquet records, 10 row groups, approximately 15.3 MiB.
  The sample was derived from the available parsed FortiGate data.
- **Machine:** Windows laptop with approximately 5.85 GiB physical RAM and 12 logical
  processors.
- **Rules:** `detection-engine/rules/detections.yaml`, unchanged for all runs.
- **Baseline:** original detector source recovered from Git commit `ebb643a`.
- **Optimized:** current `detection-engine/engine.py`, using the default 5,000-row
  input batches, 4,096-detection output buffer, and threaded PyArrow decoding.
- **Repetitions:** two runs per engine for the reported median time and observed peak
  working-set ranges. An additional monitored run per engine measured CPU and sampled
  working set. Sequential/threaded decoding was measured separately with two runs per
  setting.
- **Equivalence:** output comparison treats rows as a multiset and compares every
  output field except generated random `detection_id`; uniqueness and source references
  are checked independently.

## Baseline versus optimized

| Metric | Baseline | Optimized | Change |
|---|---:|---:|---:|
| Input records | 100,000 | 100,000 | same |
| Detections | 25,432 | 25,432 | same |
| Median wall time | 38.97 s | 3.55 s | 10.98x faster |
| Median input throughput | 2,566 records/s | 28,169 records/s | 10.98x |
| Median detection throughput | 652 detections/s | 7,164 detections/s | 10.99x |
| Peak working set across repeated runs | 1,018–1,093 MiB | 184–185 MiB | approximately 83% lower |
| Output size (representative run) | 142,320,771 bytes | 1,527,675 bytes | approximately 98.9% smaller |
| Parquet row groups | 25,432 | 7 | buffered writes |

A separately monitored run, sampled every 100 ms, took 39.90 s (baseline) and 3.68 s
(optimized). Mean process CPU use was respectively 97.1% and 81.6% of one logical
core; sampled peak working sets were 1,126.2 MiB and 179.9 MiB. Peak interval CPU was
124.4% and 115.4% of one core. This CPU sample is one run per engine; it is reported
separately from the two-run timing medians. CPU percentages are process CPU time per
wall time, not whole-machine utilization.

The baseline created one Parquet row group per detection. The optimized writer buffered
up to 4,096 detection rows per write, resulting in seven groups for the same 25,432
rows. Output byte counts can vary slightly with generated UUID values.

## Sequential versus threaded Parquet decoding

Rule evaluation stayed serial in both cases. Only the PyArrow decoding setting changed.

| Metric | Sequential read | Threaded read |
|---|---:|---:|
| Median wall time (two runs) | 4.50 s | 3.38 s |
| Peak working set | 154 MiB | 187.5 MiB |
| Mean process CPU use | 80.3% of one core | 87.8% of one core |
| Output detections | 25,432 | 25,432 |
| Semantic output differences | 0 | 0 |

Threaded decoding was about 25% faster and used approximately 33.5 MiB more peak
working set on this sample. It remains enabled by default; `--sequential-read` allows
the sequential setting to be selected. This result does not establish that threading
will be faster for all input layouts or storage devices.

## Per-rule output counts

| Rule ID | Baseline | Optimized |
|---|---:|---:|
| AUTH-001 | 13,958 | 13,958 |
| AV-001 | 1,469 | 1,469 |
| IPS-001 | 3,084 | 3,084 |
| IPS-002 | 1,968 | 1,968 |
| NET-001 | 4,497 | 4,497 |
| WEB-001 | 456 | 456 |
| **Total** | **25,432** | **25,432** |

## Interpretation and limits

Measured improvements align with the audited bottlenecks: candidate rules are indexed
by event type/subtype, only required input columns are materialized, and output is
buffered rather than written one row at a time. No rule conditions or thresholds were
changed. Rule evaluation was not parallelized because stateful aggregation and ordered
input processing make that a correctness risk without a separate ordering/state design.

The available 5.85 GiB machine was not used for 15/30/50 GB tier runs. The 100,000-row
sample does not include planted-attack ground truth, so accuracy, false-alarm rate,
full attack-path reconstruction, and large-tier performance remain unmeasured. Do not
extrapolate these figures linearly or interpret them as production-readiness evidence.
