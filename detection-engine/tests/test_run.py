import subprocess, os
inp="C:/Users/nsrn/AppData/Local/Temp/kilo/sample1000.parquet"
rules="C:/Users/nsrn/Desktop/scaratch/detection-engine/rules/detections.yaml"
out="C:/Users/nsrn/AppData/Local/Temp/kilo/test_det.parquet"
if os.path.exists(out): os.remove(out)
subprocess.run(["python","engine.py","--input",inp,"--rules",rules,"--output",out], cwd="C:/Users/nsrn/Desktop/scaratch/detection-engine", check=True)
import pyarrow.parquet as pq
md=pq.read_metadata(out)
assert md.num_rows>0
print("OK", md.num_rows)
