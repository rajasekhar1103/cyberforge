# Phase 3B — Detection Equivalence Validation

## Result

The historical baseline and optimized detector emitted semantically equivalent
detections on the same 100,000-row input and the same rules. The two output datasets
contained 25,432 rows each. A bidirectional multiset comparison of all detection
columns except the generated UUID field `detection_id` found **zero differences**.

The random detection ID is excluded from row equality because it is generated anew on
each run. Its uniqueness is validated separately.

## Validation evidence

| Check | Baseline | Optimized | Result |
|---|---:|---:|---|
| Total detections | 25,432 | 25,432 | Equal |
| Bidirectional row differences, excluding `detection_id` | 0 | 0 | Equivalent |
| Duplicate detection IDs | 0 | 0 | Pass |
| Duplicate `(rule_id, source_file, line_number)` matches | 0 | 0 | Pass |
| Detection source references absent from input | 0 | 0 | Pass |
| Parquet output columns | 20 | 20 | Same detection contract |

The optimized sequential-read and threaded-read outputs were also compared
bidirectionally, excluding only `detection_id`; they had zero semantic differences.
Each contained 25,432 detections, zero duplicate IDs, zero duplicate rule/source
pairs, and zero missing input references.

### Per-rule counts

| Rule ID | Baseline | Optimized | Result |
|---|---:|---:|---|
| AUTH-001 | 13,958 | 13,958 | Equal |
| AV-001 | 1,469 | 1,469 | Equal |
| IPS-001 | 3,084 | 3,084 | Equal |
| IPS-002 | 1,968 | 1,968 | Equal |
| NET-001 | 4,497 | 4,497 | Equal |
| WEB-001 | 456 | 456 | Equal |

## Method and scope

The baseline was recovered from Git as `ebb643a:detection-engine/engine.py`; the
optimized run used the working-tree detector. Both read the same 100,000-row Parquet
sample and `detection-engine/rules/detections.yaml`. The multiset comparison covered
all 20 output fields other than `detection_id`, so it checked rule identity and name,
category, severity, description, event attributes, source-file and line references,
evidence, matched conditions, confidence, and MITRE techniques without relying on row
order.

Source-reference integrity was checked by joining each detection's
`(source_file, line_number)` to the original sample. Duplicate IDs and duplicate
rule/source-event pairs were counted independently for each output.

The detector test suite also exercises type/subtype routing, preservation of detection
content, multi-batch writes, and equality between sequential and threaded decoding
with aggregation, generic-type, and global rules.

This validates sample-level output equivalence only. It does not measure planted
attack accuracy or establish equivalence/performance at 15/30/50 GB scale.
