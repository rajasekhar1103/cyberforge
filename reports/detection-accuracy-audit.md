# FortiGate Detection Accuracy Audit

## Summary and limits

The detector and rules were reviewed against the full parsed FortiGate dataset. The
rule behavior and performance changes below are measured, but detection accuracy is
not: the repository contains no official labeled evaluation set or ordered attack-step
ground truth. Recall, ATT&CK label accuracy, false-alarm rate, attack-path accuracy,
and unmatched ground-truth steps therefore cannot be calculated. The requested 90%,
85%, and 10% goals (over 90% planted-step recall, over 85% correct technique labels,
and under 10% false alarms) remain unverified targets, not results.

The original 5.35 GB log was parsed to 11,228,047 Parquet records (1,923,621,897
bytes). The revised detector retained the existing output schema and batch-based
streaming design.

## Pre-edit rule and parser audit

Nine rules were configured before the audit; six matched the full dataset:

| Rule | Pre-edit detections | Audit finding |
|---|---:|---|
| AUTH-001 | 1,272,524 | Matched any failed system login; no admin constraint or repetition window. Only 547,945 rows named `admin`. |
| IPS-001 | 273,176 | Matched IPS events by action. |
| IPS-002 | 177,772 | All matches overlapped IPS-001 and had high/critical source severity. |
| AV-001 | 135,623 | `action exists` matched every virus row; observed actions were 135,620 `blocked` and 3 `detected`. |
| WEB-001 | 40,857 | Matched blocked web-filter rows. |
| NET-001 | 422,103 | Matched denied forward traffic. |
| DNS-001 | 0 | All observed DNS actions were `pass`; no blocked-query example was present. |
| APP-001 | 0 | All observed application-control actions were `pass`; no block example was present. |
| VPN-001 | 0 | VPN rows had no `status` field; its `status=failed` condition did not match. |

The pre-edit total was 2,322,055 detections. IPS-001/IPS-002 emitted 177,772
duplicate source-event alerts. IPS severity was also conflated: the old IPS-002 mapped
both `high` and `critical` source events to output severity `critical`.

The parser output contained 9,133,713 `parsed` and 2,094,334 `quarantined` rows.
Among parsed rows, 8,331 lacked a usable type/subtype. Quarantined rows had parser
warnings; no parsed row had a warning in this dataset. Among quarantined rows,
2,082,789 reported invalid UTF-8, 2,012,998 reported malformed tokens, and 708
reported unterminated quoted values; warning categories overlap. For example, line
9,125,383 warned about invalid UTF-8 at byte 273 and a malformed token near byte 271.
The next line began with binary bytes and was quarantined for invalid UTF-8 and a
malformed token. The parser does not coerce these rows into parsed evidence.
Event times were 19-digit nanosecond values.

### Rule-by-rule policy review

Confidence is `null` for every rule because there is no adjudicated training/validation
set; it is not inferred from severity, rule type, or rule count. An empty
`mitre_techniques` array means unmapped, not benign. Severity describes the finding
category/rule priority and is not an attack-success label.

| Rule | Current evidence/conditions | Severity | Confidence | ATT&CK | Full-input detections |
|---|---|---|---|---|---:|
| AUTH-001 — Repeated admin login failure | `user=admin`, failed system login; 5 from one source within 600 s | medium | unvalidated (`null`) | T1110, pattern heuristic only | 14,739 |
| IPS-001 — Medium-severity IPS signature | IPS action `dropped`/`blocked`/`detected`, source severity `medium` | medium | unvalidated (`null`) | unmapped | 95,404 |
| IPS-002 — High-severity IPS signature | Same action set, source severity `high` | high | unvalidated (`null`) | unmapped | 95,719 |
| IPS-003 — Critical-severity IPS signature | Same action set, source severity `critical` | critical | unvalidated (`null`) | unmapped | 82,053 |
| AV-001 — Antivirus detection | Virus log action `blocked` or `detected` | high | unvalidated (`null`) | unmapped | 135,623 |
| DNS-001 — DNS blocked query | DNS action `block`/`blocked`/`deny`; none observed | medium | unvalidated (`null`) | unmapped | 0 |
| WEB-001 — Web filter block | Web-filter action `block`/`blocked`/`deny` | medium | unvalidated (`null`) | unmapped | 40,857 |
| APP-001 — Application control block | Application-control action `block`/`blocked`/`deny`; none observed | medium | unvalidated (`null`) | unmapped | 0 |
| NET-001 — Denied traffic | Forward action `deny`/`denied`/`drop`/`dropped` | low | unvalidated (`null`) | unmapped | 422,103 |
| VPN-001 — VPN authentication failure | VPN `status=failed`; no status values observed | medium | unvalidated (`null`) | unmapped | 0 |

These are raw detection observations, including blocked/prevented events; none proves a
successful compromise. No reliable asset, identity, or reputation enrichment source
was found in the repository or supplied evaluation files.

### ATT&CK mapping audit

- **T1110 (Brute Force):** MITRE describes repetitive or iterative credential guessing.
  The old rule’s single failed login did not support that behavior. AUTH-001 now
  requires `user=admin`, `action=login`, `status=failed`, and five events from one
  source IP within 600 seconds. It emits one alert per source during each 600-second
  cooldown. This is a brute-force-pattern heuristic, not evidence of compromise.
  Reference: <https://attack.mitre.org/techniques/T1110/>.
- **T1133 (External Remote Services):** a failed VPN status alone does not establish
  use of an external remote service. The current dataset also has no VPN status values,
  so VPN-001 had no matches. Its T1133 mapping was removed.
  Reference: <https://attack.mitre.org/techniques/T1133/>.
- No ATT&CK mappings were added to IPS, antivirus, DNS, web, application-control, or
  network rules because the available event fields do not establish a specific
  technique. Existing qualitative confidence values were not recalibrated from labels.

## Changes made

- Added bounded event-time aggregation for AUTH-001. The five-event queue is inclusive
  at the 600-second boundary; out-of-order timestamps reset that key’s history and are
  counted. Missing keys/timestamps are skipped and reported. State is capped at
  100,000 keys and 1,000,000 window events; exceeding a cap fails explicitly instead
  of silently dropping state. A threshold detection now includes the five contributing
  `(source_file, line_number)` references and aggregation parameters inside
  `matched_conditions`, without changing the 20-column detection schema.
- Split IPS detections into medium, high, and critical source-severity rules. Each
  action-eligible source event now matches one tier with corresponding output
  severity, eliminating the old overlap.
- Restricted AV-001 to the observed `blocked` and `detected` actions.
- Removed VPN-001’s unsupported T1133 mapping.
- Replaced unsupported static rule/cluster confidence values with null. These fields
  are explicitly unvalidated until a separate adjudicated validation set exists.
- The detector now excludes and reports quarantined rows, parser-warning rows,
  structurally malformed rows, missing aggregation keys/timestamps, and aggregation
  resets. Legacy Parquet files without parse-status columns remain supported and report
  quarantine counts as unavailable.
- Correlation ties now sort by source file, line number, and rule ID before generated
  detection IDs. Correlation output is named an observation cluster and its existing
  API/Parquet `incidents` schema is retained for compatibility. It is not a confirmed
  incident, proof of causality, or a ground-truth attack path.

The detection Parquet output remains 20 columns. A full-input source-reference check
resolved all 886,498 revised detections to parsed source rows (0 quarantined and 0
unresolved). AUTH aggregation evidence references all five contributing parsed rows;
parser-status and warning metadata are not added to detections.

## Same-input, same-rules evaluation

Both engines processed the same 11,228,047-row Parquet file and the same revised YAML
rules. The baseline was a preserved pre-change detector snapshot. Timings are
end-to-end wall time; input throughput divides all input rows by wall time. Peak
working set was sampled from the process every 500 ms. Output sizes are exact bytes.

| Metric | Same-rules baseline | Final strict detector |
|---|---:|---:|
| Input records | 11,228,047 | 11,228,047 |
| Detections | 1,419,018 | 886,498 |
| Wall time | 87.87 s | 89.57 s |
| Input throughput | 127,780 rows/s | 125,355 rows/s |
| Peak working set (sampled) | 1,146 MiB | 1,166 MiB |
| Output size | 75,890,887 bytes | 55,739,873 bytes |

The revised count is 37.53% lower than the same-rules baseline; the 532,520
baseline-only rows are all AUTH-001 matches suppressed by the time window/cooldown.
Separately, the IPS tier changes preserve 273,176 unique IPS source events while
removing the 177,772 duplicate rows emitted by the pre-edit overlapping rules. These
are measured output reductions, **not measured false-positive reductions**.

| Rule | Same-rules baseline | Updated |
|---|---:|---:|
| AUTH-001 | 547,259 | 14,739 |
| IPS-001 (medium) | 95,404 | 95,404 |
| IPS-002 (high) | 95,719 | 95,719 |
| IPS-003 (critical) | 82,053 | 82,053 |
| AV-001 | 135,623 | 135,623 |
| NET-001 | 422,103 | 422,103 |
| WEB-001 | 40,857 | 40,857 |
| DNS-001 / APP-001 / VPN-001 | 0 | 0 |

Comparison joined on `(rule_id, source_file, line_number)` and excluded random
`detection_id`: 886,498 rows were common, 532,520 baseline-only rows, and zero
updated-only rows. Neither output contained duplicate rule/source keys. All common
rows now have null confidence instead of the baseline's uncalibrated categories;
AUTH rows also have updated `matched_conditions` with the aggregation threshold,
window, and five contributing source references. The other compared fields matched.
The old full-run output from the pre-edit rules was preserved and not overwritten.

The updated full run reported 9,133,713 parsed rows, 2,094,334 quarantined rows, zero
parsed rows with parser warnings, 8,331 malformed structural rows, and zero missing
aggregation keys, missing event times, or out-of-order resets. Measured full-run
throughput and sampled memory are workload-specific; no function-level profiler was
used to claim a CPU bottleneck. All 14,739 AUTH detections carried five distinct source
references each: all 73,695 references resolved to parsed rows in the input, with zero
quarantined or unresolved references. Output remains 20 columns.

## Accuracy status and data needed

No real false-positive example can be confirmed without benign/malicious labels.
Synthetic negative tests cover fewer than five admin failures, successful logins,
non-admin users, unsupported IPS actions, and unsupported antivirus actions. They do
not establish real-world false-alarm rate.

The official benchmark scoring unit and deduplication policy (event, detection,
incident/cluster, or attack step) could not be located. No train/validation/test
splits or adjudicated labels are present, so confidence calibration and held-out
scoring were not performed. Precision, false-positive count/rate, recall,
technique-label accuracy, abstention rate, and complete ordered-path success are
unmeasured; the strict false-alarm goal and required recall are neither met nor
missed on evidence yet.

To finish scoring, provide an official labeled evaluation file keyed to source events
(`source_file` plus `line_number`, or a stable event ID), and its scoring specification,
with:

1. `truth_label` = `attack_step`, `benign` only after authoritative adjudication, or
   `unknown` when not labeled;
2. `attack_id`/campaign ID and integer `step_index` for each planted attack step;
3. expected ATT&CK technique IDs per step, including an explicit unmapped/unknown
   value where the benchmark expects no technique;
4. event timestamps and stable source-event references for every step;
5. representative adjudicated benign events from the same environment;
6. the benchmark unit, duplicate-detection handling, incident/cluster matching rule,
   and rules for unknown/abstained events; and
7. independent tuning/validation and held-out test split IDs, grouped by attack or
   campaign so one sequence cannot leak across splits.

That data is required to calculate recall, technique-label accuracy, false-alarm rate,
precision, ordered-path success, unmatched attack steps, and reviewed false-positive
examples. `unknown` records must not be counted as benign. Calibration must use only
the training/validation split; final metrics must use the untouched held-out split.

## Tests and reproduction

Focused tests cover the admin rule’s conditions and negative cases, inclusive window
boundaries and cooldown, parser quarantine/warning/malformed handling, bounded-state
failure, ATT&CK source references, non-overlapping IPS severity tiers, explicit AV
actions, and deterministic same-time evidence ordering.

From the repository root, rerun with new output names so existing baseline artifacts
are preserved:

```powershell
python "D:\cyberforge-run-20261101-0810\accuracy-baseline-engine.py" `
  --input "D:\cyberforge-run-20261101-0810\firex-events.parquet" `
  --rules "detection-engine\rules\detections.yaml" `
  --output "D:\cyberforge-run-20261101-0810\accuracy-baseline-repeat.parquet"

python "detection-engine\engine.py" `
  --input "D:\cyberforge-run-20261101-0810\firex-events.parquet" `
  --rules "detection-engine\rules\detections.yaml" `
  --output "D:\cyberforge-run-20261101-0810\accuracy-updated-strict-repeat.parquet"

Push-Location "detection-engine"
python -m unittest discover -s tests -p "test_engine_streaming.py"
Pop-Location

Push-Location "correlation-engine"
python -m unittest discover -s tests -p "test_streaming_correlation.py"
Pop-Location
```

To compare repeat outputs, use DuckDB to compare on the stable rule/source key while
excluding the generated UUID:

```powershell
@'
import duckdb

baseline = r"D:\cyberforge-run-20261101-0810\accuracy-baseline-repeat.parquet"
updated = r"D:\cyberforge-run-20261101-0810\accuracy-updated-repeat.parquet"
db = duckdb.connect()
for label, path in (("baseline", baseline), ("updated", updated)):
    print(label)
    print(db.execute(
        "select rule_id, count(*) detections from read_parquet(?) "
        "group by rule_id order by rule_id", [path]
    ).fetchall())

print(db.execute(
    "select "
    "(select count(*) from read_parquet(?) b anti join read_parquet(?) u "
    "using(rule_id,source_file,line_number)) baseline_only, "
    "(select count(*) from read_parquet(?) u anti join read_parquet(?) b "
    "using(rule_id,source_file,line_number)) updated_only",
    [baseline, updated, updated, baseline],
).fetchall())

compared_columns = [
    "rule_name", "category", "severity", "description", "srcip", "dstip",
    "username", "host", "eventtime", "date", "time", "tz", "evidence",
    "matched_conditions", "confidence", "mitre_techniques",
]
mismatch = " or ".join(
    f"b.{column} is distinct from u.{column}" for column in compared_columns
)
query = (
    "select count(*) common_rows, "
    f"count(*) filter(where {mismatch}) semantic_mismatches "
    "from read_parquet(?) b join read_parquet(?) u "
    "using(rule_id,source_file,line_number)"
)
print(db.execute(query, [baseline, updated]).fetchall())
'@ | python -
```
