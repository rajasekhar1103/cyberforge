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

- The commands support desktop Windows (PowerShell) and macOS/Linux (Bash); they
  are not mobile-device instructions. Start commands from the repository root.
- Rust stable with Cargo, for the parser.
- Python 3.10 or newer and pip.
- A FortiGate log file. `firex-10G.log` is not tracked by Git (the repository
  ignores `*.log`), so provide that file separately or set the input path to your
  own log.
- Free disk space for the input, parsed Parquet, detections, correlation outputs,
  and DuckDB temporary files. The example 5.35 GB log requires substantially more
  than 5.35 GB of free space to process; there is no universal minimum because
  output and spill sizes depend on the input. The graph builder also loads its
  inputs into memory.
- The dashboards bind to `127.0.0.1` in these examples and are reachable from the
  same machine only.

### Set up Python and Rust

From the repository root in Windows PowerShell:

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

On macOS or Linux, use Bash:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-api-dev.txt -r requirements-dashboard.txt pyarrow PyYAML networkx requests
cargo build --release --manifest-path cyberforge-parser/Cargo.toml
```

## Run the pipeline

Run from the repository root in one PowerShell window. Run each numbered block in
order in that same window; later steps use variables created in step 1.
`firex-10G.log` is not included in Git, so change `$InputLogPath` to the path of a
FortiGate log you have provided. Each run creates a new output directory rather
than replacing previous results. By default, output is stored under the repository's
`data` folder. If that drive does not have enough free space, set
`$env:CYBERFORGE_OUTPUT_DIR` to a folder on a drive with enough free space before
running step 1; for example, `D:\CyberForge\data`.

### 1. Parse the log

```powershell
$InputLogPath = '.\firex-10G.log'
if (-not (Test-Path -LiteralPath $InputLogPath -PathType Leaf)) {
  throw "Log file not found: $InputLogPath"
}
$InputLog = (Resolve-Path -LiteralPath $InputLogPath).Path
$RunRoot = if ($env:CYBERFORGE_OUTPUT_DIR) {
  $env:CYBERFORGE_OUTPUT_DIR
} else {
  Join-Path (Get-Location).Path 'data'
}
New-Item -ItemType Directory -Force -Path $RunRoot | Out-Null
$RunDirectory = Join-Path $RunRoot ("run-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $RunDirectory -ErrorAction Stop | Out-Null
$Events = Join-Path $RunDirectory 'firex-events.parquet'
$Detections = Join-Path $RunDirectory 'detections.parquet'
Write-Host "Writing outputs to $RunDirectory"

cargo run --release --manifest-path .\cyberforge-parser\Cargo.toml -- `
  --input $InputLog `
  --output $Events
if ($LASTEXITCODE -ne 0) { throw 'Log parsing failed' }
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

This reads the parsed events and YAML rules, then writes matching observations to
`detections.parquet`.

```powershell
if (-not (Test-Path -LiteralPath $Events -PathType Leaf)) {
  throw "Parsed events not found: $Events. Run step 1 first."
}

python .\detection-engine\engine.py `
  --input $Events `
  --rules .\detection-engine\rules\detections.yaml `
  --output $Detections
if ($LASTEXITCODE -ne 0) { throw 'Detection failed' }
if (-not (Test-Path -LiteralPath $Detections -PathType Leaf)) {
  throw "Detection output was not created: $Detections"
}
Write-Host "Detections written to $Detections"
```

The detector defaults to 5,000-row batches. It prints progress and a final summary.
To disable PyArrow's parallel Parquet decoding, add `--sequential-read`.

### 3. Correlate detections (required before building a graph)

This groups detections into time-related observation clusters. It creates the
incident and detection-to-cluster Parquet files needed by the graph and
investigation dashboard. Run this step before step 4 and before starting the
investigation dashboard/API. It is optional only if you are using the direct
detection dashboard and do not need a graph. Correlation does not prove causation
or compromise.

```powershell
if (-not (Test-Path -LiteralPath $Detections -PathType Leaf)) {
  throw "Detections not found: $Detections. Run step 2 first."
}

$Incidents = Join-Path $RunDirectory 'incidents.parquet'
$Relations = Join-Path $RunDirectory 'incident_detections.parquet'
$Temp = Join-Path $env:TEMP ("cyberforge-correlation-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $Temp | Out-Null

python .\correlation-engine\correlate.py `
  --detections $Detections `
  --out-incidents $Incidents `
  --out-rel $Relations `
  --window 3600000000000 `
  --memory-limit 512MB `
  --temp-directory $Temp
if ($LASTEXITCODE -ne 0) { throw 'Correlation failed' }
foreach ($Path in @($Incidents, $Relations)) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Correlation output was not created: $Path"
  }
}
Write-Host "Observation clusters written to $Incidents"
Write-Host "Cluster links written to $Relations"
```

The default correlation window is one hour in the nanosecond units used by
FortiGate `eventtime`. Correlation indicates shared-source temporal proximity; it
does not establish causality or a confirmed attack path.

### 4. Build a graph (optional)

This creates a JSON graph from the detection and correlation outputs. The graph
builder loads its input into memory, so start with a small log if your machine has
limited RAM.

```powershell
if ([string]::IsNullOrWhiteSpace($Detections)) {
  throw 'Detections path is not set. Run step 2 first, or set $Detections to your detections.parquet path.'
}
if (-not (Test-Path -LiteralPath $Detections -PathType Leaf)) {
  throw "Detections not found: $Detections. Run step 2 first."
}

$RunDirectory = Split-Path -Parent $Detections
$Incidents = Join-Path $RunDirectory 'incidents.parquet'
$Relations = Join-Path $RunDirectory 'incident_detections.parquet'
foreach ($Path in @($Incidents, $Relations)) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Required graph input not found: $Path. Run step 3 (correlation) first."
  }
}

$Graph = Join-Path $RunDirectory 'graph.json'
python .\graph-engine\graph.py `
  --detections $Detections `
  --incidents $Incidents `
  --relations $Relations `
  --out $Graph
if ($LASTEXITCODE -ne 0) { throw 'Graph generation failed' }
if (-not (Test-Path -LiteralPath $Graph -PathType Leaf)) {
  throw "Graph output was not created: $Graph"
}
Write-Host "Graph written to $Graph"
```

The API also enforces graph size limits; see [API and data contracts](docs/api-data-contracts.md).

### macOS/Linux (Bash)

The following block runs the parser, detector, correlator, and graph builder. Set
`INPUT_LOG` to the path of a log you have provided. A new output directory is
created for each run.

```bash
set -e
INPUT_LOG="$PWD/firex-10G.log"
if [ ! -f "$INPUT_LOG" ]; then
  printf 'Log file not found: %s\n' "$INPUT_LOG" >&2
  exit 1
fi
mkdir -p data
RUN_DIR="data/run-$(date +%Y%m%d-%H%M%S)-$$"
mkdir "$RUN_DIR"
EVENTS="$PWD/$RUN_DIR/firex-events.parquet"
DETECTIONS="$PWD/$RUN_DIR/detections.parquet"
INCIDENTS="$PWD/$RUN_DIR/incidents.parquet"
RELATIONS="$PWD/$RUN_DIR/incident_detections.parquet"
GRAPH="$PWD/$RUN_DIR/graph.json"
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cyberforge-correlation.XXXXXX")"
printf 'Writing outputs to %s\n' "$RUN_DIR"

cargo run --release --manifest-path cyberforge-parser/Cargo.toml -- \
  --input "$INPUT_LOG" \
  --output "$EVENTS"

cargo run --release --manifest-path cyberforge-parser/Cargo.toml -- \
  --input "$INPUT_LOG" \
  --scan-timestamps

python detection-engine/engine.py \
  --input "$EVENTS" \
  --rules detection-engine/rules/detections.yaml \
  --output "$DETECTIONS"

python correlation-engine/correlate.py \
  --detections "$DETECTIONS" \
  --out-incidents "$INCIDENTS" \
  --out-rel "$RELATIONS" \
  --window 3600000000000 \
  --memory-limit 512MB \
  --temp-directory "$TEMP_DIR"

python graph-engine/graph.py \
  --detections "$DETECTIONS" \
  --incidents "$INCIDENTS" \
  --relations "$RELATIONS" \
  --out "$GRAPH"
```

## View results

### Direct detection dashboard

This view needs only the detections Parquet output. In a new PowerShell window from
the repository root, set `$RunDirectory` to the path printed by the pipeline:

```powershell
$RunDirectory = 'C:\path\to\data\run-<id>'
$env:CYBERFORGE_DETECTIONS_PATH = (Resolve-Path (Join-Path $RunDirectory 'detections.parquet')).Path
python -m streamlit run .\dashboard\detection_results.py `
  --server.address 127.0.0.1 `
  --server.port 8502
```

Open <http://127.0.0.1:8502>. It provides summary charts, filters, paginated
detections, and an evidence-linked activity-path view. Activity paths are
visualizations of observations and ordering, not proof of causation.

On macOS or Linux, set the detection path to the run directory printed by the Bash
pipeline, then start the same view:

```bash
export CYBERFORGE_DETECTIONS_PATH="$PWD/data/run-<id>/detections.parquet"
python -m streamlit run dashboard/detection_results.py \
  --server.address 127.0.0.1 \
  --server.port 8502
```

### Investigation dashboard and API

The investigation dashboard requires all four files in the configured data
directory: `detections.parquet`, `incidents.parquet`,
`incident_detections.parquet`, and `graph.json`. After completing the optional
correlation and graph steps, start the API in one PowerShell window. Set
`$RunDirectory` to the same output directory:

```powershell
$RunDirectory = 'C:\path\to\data\run-<id>'
$env:CYBERFORGE_DATA_DIR = (Resolve-Path $RunDirectory).Path
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

On macOS or Linux, set the dataset path and start the API:

```bash
export CYBERFORGE_DATA_DIR="$PWD/data/run-<id>"
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

In another terminal:

```bash
export CYBERFORGE_API_URL='http://127.0.0.1:8000'
python -m streamlit run dashboard/app.py \
  --server.address 127.0.0.1 \
  --server.port 8501
```

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
if ($LASTEXITCODE -ne 0) { throw 'Rust parser tests failed' }
```

Run the focused Python detection and correlation tests:

```powershell
Push-Location .\detection-engine
try {
  python -m unittest discover -s tests -p "test_engine_streaming.py"
  if ($LASTEXITCODE -ne 0) { throw 'Detection tests failed' }
} finally {
  Pop-Location
}

Push-Location .\correlation-engine
try {
  python -m unittest discover -s tests -p "test_streaming_correlation.py"
  if ($LASTEXITCODE -ne 0) { throw 'Correlation tests failed' }
} finally {
  Pop-Location
}
```

API tests are in `tests\test_api.py`; run them with:

```powershell
python -m unittest discover -s tests -p "test_api.py"
if ($LASTEXITCODE -ne 0) { throw 'API tests failed' }
```

The API tests create and clean up their own synthetic Parquet and graph fixtures.
They do not require a large log or a user-specific temporary directory. The
detection and correlation test commands change into their component directories so
their local module imports resolve correctly.

On macOS or Linux, run the same suites with:

```bash
set -e
cargo test --manifest-path cyberforge-parser/Cargo.toml
(cd detection-engine && python -m unittest discover -s tests -p 'test_engine_streaming.py')
(cd correlation-engine && python -m unittest discover -s tests -p 'test_streaming_correlation.py')
python -m unittest discover -s tests -p 'test_api.py'
```

## Further documentation

- [Detection accuracy audit](reports/detection-accuracy-audit.md)
- [Dashboard quickstart](docs/dashboard-quickstart.md)
- [API design](docs/api-design.md)
- [API data contracts](docs/api-data-contracts.md)
- [Correlation engine](docs/correlation-engine.md)
