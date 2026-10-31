import duckdb, subprocess, time
I="C:/Users/nsrn/AppData/Local/Temp/kilo/incidents.parquet"
R="C:/Users/nsrn/AppData/Local/Temp/kilo/incident_detections.parquet"
D="C:/Users/nsrn/AppData/Local/Temp/kilo/detections.parquet"
c=duckdb.connect()
print("incidents", c.execute(f"SELECT count(*) FROM read_parquet('{I}')").fetchone()[0])
print("min/max/avg/median", c.execute(f"SELECT min(detection_count),max(detection_count),avg(detection_count),median(detection_count) FROM read_parquet('{I}')").fetchone())
print("assigned", c.execute(f"SELECT count(*) FROM read_parquet('{R}')").fetchone()[0])
print("dup rels", c.execute(f"SELECT count(*) FROM (SELECT detection_id FROM read_parquet('{R}') GROUP BY 1 HAVING count(*)>1)").fetchone()[0])
print("unresolved", c.execute(f"SELECT count(*) FROM read_parquet('{R}') r LEFT JOIN read_parquet('{D}') d ON r.detection_id=d.detection_id WHERE d.detection_id IS NULL").fetchone()[0])
