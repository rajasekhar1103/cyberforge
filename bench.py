import time, subprocess
start=time.time()
subprocess.run(["python","correlate.py","--detections","C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet","--out-incidents","C:/Users/nsrn/AppData/Local/Temp/kilo/incidents.parquet","--out-rel","C:/Users/nsrn/AppData/Local/Temp/kilo/incident_detections.parquet","--window","3600000000000"], cwd="C:/Users/nsrn/Desktop/scaratch/correlation-engine", check=True)
print("elapsed", round(time.time()-start,4))
