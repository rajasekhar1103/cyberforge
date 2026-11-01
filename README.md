# CyberForge

CyberForge is a FortiGate log analysis project. It parses raw logs into Parquet,
applies configurable evidence-based detection rules, groups related detections into
observation clusters, and provides dashboards for exploring the results.

> **Important:** a detection or observation cluster is not proof of compromise.
> Confidence is currently uncalibrated (`null`). There is no official labeled
> evaluation set in this repository, so precision, recall, false-alarm rate, and
> ATT&CK label accuracy have not been measured.

## What it does

1. **Parse:** A Rust command-line parser reads FortiGate logs and writes Parquet
   batches. It records malformed or quarantined input explicitly. It can also scan
   timestamps without producing Parquet.
2. **Detect:** A Python streaming detector reads parsed Parquet batches and applies
   YAML rules. The current rules include a repeated failed admin-login pattern,
   distinct IPS severity tiers, antivirus actions, blocked web traffic, and denied
   traffic.
3. **Correlate:** A DuckDB-backed Python process sorts detections and groups
   time-related observations into clusters. It uses a configurable memory limit and
   can spill sort work to a temporary directory.
4. **Visualize:** A Streamlit detection-results page can inspect a detection Parquet
   file directly. A second dashboard uses the FastAPI investigation service to show
   incidents/clusters, timelines, and bounded graph views.

## Technology stack

| Area | Technologies |
|---|---|
| Log parser | Rust 2021, Arrow, Parquet, Clap, Rayon |
| Detection | Python, PyArrow, PyYAML, YAML rules |
| Correlation | Python, DuckDB, PyArrow |
| API | FastAPI, Uvicorn, DuckDB |
| Dashboards | Streamlit, Pandas |
| Graph generation | Python, NetworkX, PyArrow |
| Data format | Apache Parquet / Arrow and JSON graph data |

## Requirements

- Windows PowerShell examples below assume the repository root is the current
  directory.
- Rust stable with Cargo, for the parser.
- Python 3.10 or newer and pip.
- Disk space for input logs, Parquet outputs, and DuckDB temporary files. The
  supplied `firex-10G.log` is about 5.35 GB; the parsed Parquet file is also large.

### Set up Python and Rust

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-api-dev.txt -r requirements-dashboard.txt pyarrow PyYAML networkx requests
cargo build --release --manifest-path .\cyberforge-parser\Cargo.toml
```

If PowerShell blocks virtual-environment activation, either adjust the local
execution policy according to your organization's guidance or run the environment's
Python directly at `.venv\Scripts\python.exe`.

## Run the pipeline

The following commands use the included `firex-10G.log` and keep generated files in
an untracked `data\run` directory. They do not overwrite existing outputs without
confirmation.

```powershell
New-Item -ItemType Directory -Force .\data\run | Out-Null
$InputLog = (Resolve-Path .\firex-10G.log).Path
$Events = (Join-Path (Resolve-Path .\data\run).Path 'firex-events.parquet')
$Detections = (Join-Path (Resolve-Path .\data\run).Path 'detections.parquet')
```

### 1. Parse the log

```powershell
cargo run --release --manifest-path .\cyberforge-parser\Cargo.toml -- `
  --input $InputLog `
  --output $Events
```

The parser defaults to batches of 1,000 records and two worker threads. Tune with
`--batch-size` and `--threads` only after measuring on your machine.

To scan timestamps only (no Parquet output):

```powershell
cargo run --release --manifest-path .\cyberforge-parser\Cargo.toml -- `
  --input $InputLog `
  --scan-timestamps
```

### 2. Run detection

```powershell
python .\detection-engine\engine.py `
  --input $Events `
  --rules .\detection-engine\rules\detections.yaml `
  --output $Detections
```

The detector defaults to 5,000-row batches. It prints progress and a final summary.
To disable PyArrow's parallel Parquet decoding, add `--sequential-read`.

### 3. (Optional) Correlate detections

```powershell
$Incidents = Join-Path (Resolve-Path .\data\run).Path 'incidents.parquet'
$Relations = Join-Path (Resolve-Path .\data\run).Path 'incident_detections.parquet'
$Temp = Join-Path $env:TEMP 'cyberforge-correlation'
New-Item -ItemType Directory -Force $Temp | Out-Null

python .\correlation-engine\correlate.py `
  --detections $Detections `
  --out-incidents $Incidents `
  --out-rel $Relations `
  --window 3600000000000 `
  --memory-limit 512MB `
  --temp-directory $Temp
```

The default correlation window is one hour in the nanosecond units used by
FortiGate `eventtime`. Correlation indicates shared-source temporal proximity; it
does not establish causality or a confirmed attack path.

### 4. (Optional) Build a graph

```powershell
$Graph = Join-Path (Resolve-Path .\data\run).Path 'graph.json'
python .\graph-engine\graph.py `
  --detections $Detections `
  --incidents $Incidents `
  --relations $Relations `
  --out $Graph
```

The current graph builder materializes its input in memory. Start with a manageable
dataset and check available RAM before using it on a full large-log output. The API
also enforces graph size limits; see [API and data contracts](docs/api-data-contracts.md).

## View results

### Direct detection dashboard

This view needs only the detections Parquet output. In a new PowerShell window from
the repository root:

```powershell
$env:CYBERFORGE_DETECTIONS_PATH = (Resolve-Path .\data\run\detections.parquet).Path
python -m streamlit run .\dashboard\detection_results.py `
  --server.address 127.0.0.1 `
  --server.port 8502
```

Open <http://127.0.0.1:8502>. It provides summary charts, filters, paginated
detections, and an evidence-linked activity-path view. Activity paths are
visualizations of observations and ordering, not proof of causation.

### Investigation dashboard and API

The investigation dashboard requires all four files in the configured data
directory: `detections.parquet`, `incidents.parquet`,
`incident_detections.parquet`, and `graph.json`. After completing the optional
correlation and graph steps, start the API in one PowerShell window:

```powershell
$env:CYBERFORGE_DATA_DIR = (Resolve-Path .\data\run).Path
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

In another window:

```powershell
$env:CYBERFORGE_API_URL = 'http://127.0.0.1:8000'
python -m streamlit run .\dashboard\app.py `
  --server.address 127.0.0.1 `
  --server.port 8501
```

Open <http://127.0.0.1:8501>. The API is read-only and binds to localhost in these
examples. Do not expose it to an untrusted network without adding appropriate
authentication, authorization, and deployment safeguards.

## Achievements and measured results

The latest same-input detector comparison used 11,228,047 Parquet rows and identical
rules:

| Measurement | Preserved baseline | Updated detector |
|---|---:|---:|
| Detections | 1,419,018 | 886,498 |
| Wall time | 87.87 s | 89.57 s |
| Input throughput | 127,780 rows/s | 125,355 rows/s |
| Sampled peak working set | 1,146 MiB | 1,166 MiB |
| Output size | 75,890,887 bytes | 55,739,873 bytes |

### Planted-attack target scorecard

The targets below are the requested benchmark goals. “Not measured” means the
repository has no official planted-attack ground truth and scoring specification;
it does not mean the system scored zero.

| What we measure | Good target | Great target | Current result on this run | Assessment |
|---|---:|---:|---|---|
| Detection — share of planted attack steps found | >70% | >90% | Not measured: no labeled planted-step set | Cannot score |
| Correct labels — found steps with correct ATT&CK technique | >60% | >85% | Not measured: no expected technique labels | Cannot score |
| Attack path — planted attacks reconstructed with all steps in order | At least half | All | Not measured: no labeled attack IDs/step order | Cannot score |
| False alarms — incidents that are not real attacks | <30% | <10% | Not measured: no adjudicated benign/attack labels or scoring unit | Cannot score |
| Processing time — full chosen tier | <3 hours | <1 hour | Detector stage: **89.57 s** for 11,228,047 Parquet rows | Great for detector stage; total parse-to-results time not measured |
| Memory — peak during processing | <16 GB | <8 GB | Detector sampled peak working set: **1,166 MiB** (~1.14 GiB) | Great for detector stage; sampled every 500 ms |
| Investigation speed — open one incident attack path | <2 s | <500 ms | Not measured with a defined repeated latency benchmark | Cannot score |

The processing and memory observations cover the updated detector run, not the
complete parse → detect → correlate → graph → dashboard workflow. The detector
comparison showed slightly longer runtime and higher sampled working set than its
preserved baseline, despite lower output volume. A ground-truth score requires a
labeled evaluation file with stable source-event references, attack/campaign IDs,
ordered step indices, expected techniques, adjudicated benign examples, a scoring
unit/deduplication policy, and a held-out test split. See the
[audit's scoring requirements](reports/detection-accuracy-audit.md#accuracy-status-and-data-needed).

Changes include:

- On identical rules and input, the updated detector emits 37.53% fewer rows and
  produces a 26.55% smaller Parquet output. This is a measured reduction in output
  volume, not evidence by itself of faster execution or fewer false alarms.
- AUTH-001 now requires five failed admin logins from the same source IP within
  600 seconds. Each alert retains references to all five contributing parsed rows.
- IPS rules are split by source severity, eliminating 177,772 duplicate
  rule/source-event alerts from the earlier overlapping rules.
- Antivirus matching is limited to the supported `blocked` and `detected` actions.
- Unsupported VPN/T1133 mapping was removed; rule confidence is null until calibrated.
- Quarantined, warning-bearing, and structurally malformed input is explicitly
  counted/handled rather than silently treated as clean evidence.
- Correlation ties have deterministic ordering, and correlated outputs are described
  as observation clusters rather than confirmed incidents.
- The Rust timestamp-only scanner was previously run on the supplied log and reported
  9,125,383 timestamps in about 40.9 seconds.

### Accuracy status

The accuracy work improves evidence quality and makes several rules more specific:
repeated admin failures are aggregated instead of alerting on every failed login,
overlapping IPS tiers no longer duplicate alerts, unsupported AV/VPN evidence does
not produce those labels, and quarantined or malformed rows are not silently treated
as clean evidence. All 73,695 event references attached to the 14,739 AUTH-001
aggregates resolved to parsed source rows.

These are rule and data-quality improvements, **not a measured accuracy score**.
There is no official labeled ground truth in the repository, so precision, recall,
false-alarm rate, ATT&CK label accuracy, and ordered attack-path success remain
unmeasured. Do not interpret fewer detections as proof of fewer false positives.
The stricter detector took slightly longer and used slightly more sampled peak memory
in the full-run comparison; its measured benefit here is reduced output volume,
deduplicated IPS observations, and stronger evidence provenance—not a throughput gain.
See the
[detection accuracy audit](reports/detection-accuracy-audit.md) for rule counts,
parser statistics, methodology, and the scoring-data requirements.

### Benchmark machine and software

The full detector run was measured on this laptop:

| Component | Configuration |
|---|---|
| Laptop | ASUS Vivobook X1605VA |
| CPU | 13th Gen Intel Core i5-13500H |
| Physical memory | 16 GB class; Windows reports approximately 15.6 GiB |
| Graphics | Intel Iris Xe Graphics |
| Operating system | Windows 11 Home Single Language, build 26300 |
| Python | 3.14.4 |
| Rust compiler | rustc 1.99.1 |
| Cargo | 1.99.1 |

These are the recorded environment details for this run, not a minimum or recommended
production configuration. Runtime and working-set results depend on the machine,
disk, background load, and input.

## Tests

Run the focused Rust parser tests:

```powershell
cargo test --manifest-path .\cyberforge-parser\Cargo.toml
```

Run the focused Python detection and correlation tests:

```powershell
Push-Location .\detection-engine
python -m unittest discover -s tests -p "test_engine_streaming.py"
Pop-Location

Push-Location .\correlation-engine
python -m unittest discover -s tests -p "test_streaming_correlation.py"
Pop-Location
```

API tests are in `tests\test_api.py`; run them with:

```powershell
python -m unittest discover -s tests -p "test_api.py"
```

## Further documentation

- [Detection accuracy audit](reports/detection-accuracy-audit.md)
- [Dashboard quickstart](docs/dashboard-quickstart.md)
- [API design](docs/api-design.md)
- [API data contracts](docs/api-data-contracts.md)
- [Correlation engine](docs/correlation-engine.md)
