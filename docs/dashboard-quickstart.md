# Investigation Dashboard Quickstart

The Streamlit dashboard is a read-only frontend for the FastAPI investigation service. It displays summary metrics, severity/category charts, filtered incidents, incident details, timelines, bounded graph relationships, technique counts, and detection details.

## Install

Run from the project root:

```powershell
python -m pip install -r requirements-api.txt -r requirements-dashboard.txt requests
```

On macOS or Linux, the same install command works in Bash after activating the
project's virtual environment:

```bash
python -m pip install -r requirements-api.txt -r requirements-dashboard.txt requests
```

## Start the API

The API and dashboard run as separate local processes. Point the API at a complete analytics output directory:

```powershell
$env:CYBERFORGE_DATA_DIR = 'C:\path\to\analytics'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

For a run created by the root README pipeline, set the directory to that run's
output path:

```powershell
$env:CYBERFORGE_DATA_DIR = 'C:\path\to\data\run-<id>'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

## Start the dashboard

In another PowerShell window:

```powershell
$env:CYBERFORGE_API_URL = 'http://127.0.0.1:8000'
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Open `http://127.0.0.1:8501`. The API address can also be changed in the dashboard sidebar.

On macOS or Linux, start the API from the project root:

```bash
export CYBERFORGE_DATA_DIR="$PWD/data/run-<id>"
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

In another terminal:

```bash
export CYBERFORGE_API_URL='http://127.0.0.1:8000'
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

## View a detection Parquet file directly

The detection-results page visualizes a detection Parquet file without requiring the
incident, relationship, and graph stores used by the investigation dashboard:

```powershell
$env:CYBERFORGE_DETECTIONS_PATH = 'D:\path\to\firex-detections.parquet'
python -m streamlit run dashboard/detection_results.py --server.address 127.0.0.1 --server.port 8502
```

On macOS or Linux:

```bash
export CYBERFORGE_DETECTIONS_PATH="$PWD/data/run-<id>/detections.parquet"
python -m streamlit run dashboard/detection_results.py --server.address 127.0.0.1 --server.port 8502
```

Open `http://127.0.0.1:8502`. The page shows severity, rule, category, and date
charts, plus a filterable, paginated findings table. The dashboard reads bounded
Parquet pages rather than loading all detections into memory.

The **Activity path** tab starts from a high-severity finding and shows nearby
events from the same source IP. It merges multiple rule hits on the same source
line, excludes timestamps shared by more than 1,000 source events, and caps the
display to six events. Solid graph edges are fields observed in the detection;
dashed links indicate time order only and are not proof of causation or compromise.
Rule confidence describes the detector match, not proof that an attack succeeded.

## Limitations

The dashboard uses the API's configured dataset and therefore reflects its snapshot and response limits. The sample artifacts are suitable for functional exploration only; no large-dataset dashboard or HTTP load benchmark has been run. The interface does not add authentication, authorization, redaction, or mutation behavior.
