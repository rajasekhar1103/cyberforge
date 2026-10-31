# Phase 3B — Detection Engine Performance Audit

## Scope and evidence

Reviewed the current `detection-engine/engine.py`, YAML rules, the parser's Parquet
schema and streaming design, existing 1,000-row detection output, detection validation
and quality reports, and prior local benchmarks. The original detector is preserved in
Git history at `ebb643a:detection-engine/engine.py`; it is the baseline implementation
for this phase. No parser, correlation, graph, or API code is in scope.

The parser emits one Parquet row per input record. Required detection inputs are
`type`, `subtype`, `fields_json`, `source_file`, and `line_number`; the rule fields are
inside `fields_json`. The existing development sample has 1,000 rows, 48 distinct
fields, no malformed records, and 12 type/subtype combinations. The original validated
output has 258 detections across six rule IDs, 237 unique source events, and no
duplicate rule/source pairs. All 258 source references resolve.

## Bottlenecks found in the original implementation

1. **Every rule was considered for every input row.** The original loop called
   `eval_rule` for every rule, including rules whose configured log type/subtype could
   not match the event. `eval_rule` reparsed each rule's log-type strings on every
   evaluation.
2. **Wide rows were materialized unnecessarily.** `iter_batches` read all parser
   columns and `to_pydict()` converted them all, even though detection only needs five
   columns.
3. **Per-match output performed repeated Python/Arrow work.** For every detection, the
   original implementation built a one-row Arrow table and called `write_table`
   separately. The existing output consequently had 258 row groups for 258 rows.
4. **Matched conditions and metadata were rebuilt at match time.** Rule metadata,
   condition lists, evidence maps, and their JSON representations were recreated for
   every match.
5. **The path is sequential.** Detection evaluation is Python CPU work and rules may
   have stateful aggregation counters. Parallel event processing would require
   ordered state merging and output sequencing; blindly parallelizing can change
   threshold behavior and increase memory.

## Current branch optimizations observed

The current engine already indexes enabled rules by event type/subtype, caches the
candidate tuple for each encountered type pair, projects the five required input
columns, skips field JSON parsing for events with no eligible rules, and buffers up to
4,096 detections before Parquet writes. Its writer uses Zstandard and the output schema
matches the existing 20-column detection contract.

Previous local measurements on a 100 MB log prefix found batch size 5,000 faster than
1,000 or 10,000 rows, with 171 MiB observed peak working set. A prior full-file run on
the then-current implementation processed 13,752,384 rows in 166.41 seconds, produced
2,322,055 detections, and peaked at 399 MiB. Those are historical single runs, not a
baseline-versus-optimized comparison; this phase will compare the Git-preserved baseline
and current engine on identical sample data before making further optimizations.

## Proposed changes and experiment

- Preserve the current candidate index, narrow-column projection, bounded row batches,
  and buffered Parquet output.
- Only add precompiled condition evaluators if profiling/benchmarks show a measurable
  benefit and equivalence tests cover every supported operator.
- Benchmark the Git-preserved baseline and current engine on exactly the same parsed
  Parquet sample and YAML rules. Compare outputs semantically, excluding only generated
  random detection IDs; independently verify ID uniqueness and source references.
- Measure wall time, input rows/sec, detections/sec, process working-set peak, sampled
  CPU utilization, output bytes, row-group counts, per-rule counts, duplicate
  source/rule pairs, and missing source references.
- Test batch size and PyArrow read-thread settings sequentially. Do not introduce
  multiprocessing unless an experiment demonstrates a benefit without changing
  aggregation semantics, event ordering, output contracts, or bounded-memory behavior.

No correctness threshold, severity, confidence, evidence mapping, field, or detection
rule will be changed to improve speed. The local sample does not contain planted attack
ground truth, so it cannot establish attack-detection accuracy or production readiness.

## Phase 3B results and decisions

The Git-preserved baseline and optimized engine were run with the same 100,000-row
Parquet sample and the same detection rules. Both emitted 25,432 detections. Comparing
all output columns except the intentionally random `detection_id` produced zero
differences in either direction. Per-rule counts, ID uniqueness, duplicate rule/source
pairs, and source references also matched. Full benchmark and validation details are in
[`detection-optimization-benchmark.md`](./detection-optimization-benchmark.md) and
[`detection-equivalence-validation.md`](./detection-equivalence-validation.md).

The baseline median was 38.97 seconds and the optimized median was 3.55 seconds
(10.98x faster). The optimized run used substantially less memory and wrote the same
detections in seven buffered row groups rather than 25,432 one-row groups. A separate
sequential-versus-threaded read comparison found threaded PyArrow decoding faster on
this sample, so it remains enabled by default; `--sequential-read` is available for
reproducibility and comparison. Detection evaluation itself remains sequential because
aggregation state and event order must not change.

No additional rule-condition compilation was justified by this comparison, and no
detection criteria or thresholds were changed. The benchmark is a small comparative
sample only. No 15/30/50 GB tier was run, planted-attack accuracy was not measured, and
these results do not establish large-scale production readiness.
