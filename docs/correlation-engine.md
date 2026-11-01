# Correlation Engine

# Correlation Engine

The correlation engine sorts detections by source IP and numeric event time with DuckDB,
then walks the sorted result in batches. These rows are observation clusters, not
confirmed incidents or successful compromises. Their confidence is null until
calibrated against adjudicated labels. Tied event times are ordered by source file,
line number, and rule ID before the generated detection ID so evidence order is stable.
This preserves the existing source-IP, chained time-window clustering behavior without
loading every detection into Python memory.
DuckDB is limited to 512 MB by default and spills sort work to a configurable temporary
directory on disk. Incident and incident-detection Parquet outputs are buffered.

`--window` is measured in the nanosecond units of FortiGate `eventtime`; the default
`3600000000000` is one hour. Correlated events indicate shared-source temporal
proximity, not proof of an attack sequence.

```powershell
python correlate.py --detections detections.parquet `
  --out-incidents incidents.parquet `
  --out-rel incident_detections.parquet `
  --window 3600000000000 `
  --memory-limit 512MB `
  --temp-directory C:\temp\cyberforge-correlation
```

The row buffers are bounded, but one incident's `detection_ids` and `evidence_refs`
fields are JSON arrays in the existing schema; a single exceptionally large cluster
therefore still requires memory proportional to that cluster.
Review [correlation-benchmark.md](../reports/correlation-benchmark.md) before choosing
a benchmark tier.
