# Investigation Dashboard Quickstart

The Streamlit dashboard is a read-only frontend for the FastAPI investigation service. It displays summary metrics, severity/category charts, filtered incidents, incident details, timelines, bounded graph relationships, technique counts, and detection details.

## Install

Run from the project root:

```powershell
python -m pip install -r requirements-dashboard.txt
```

## Start the API

The API and dashboard run as separate local processes. Point the API at a complete analytics output directory:

```powershell
$env:CYBERFORGE_DATA_DIR = 'C:\path\to\analytics'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

For the currently inspected functional sample:

```powershell
$env:CYBERFORGE_DATA_DIR = 'C:\Users\nsrn\AppData\Local\Temp\kilo'
python -m uvicorn api.app:app --host 127.0.0.1 --port 8000 --workers 1
```

## Start the dashboard

In another PowerShell window:

```powershell
$env:CYBERFORGE_API_URL = 'http://127.0.0.1:8000'
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
```

Open `http://127.0.0.1:8501`. The API address can also be changed in the dashboard sidebar.

## Limitations

The dashboard uses the API's configured dataset and therefore reflects its snapshot and response limits. The sample artifacts are suitable for functional exploration only; no large-dataset dashboard or HTTP load benchmark has been run. The interface does not add authentication, authorization, redaction, or mutation behavior.
