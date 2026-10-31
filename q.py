import duckdb, json
c=duckdb.connect()
for f in ["detections","incidents","incident_detections"]:
    p=f"C:/Users/nsrn/AppData/Local/Temp/kilo/{f}.parquet"
    row=c.execute(f"SELECT * FROM read_parquet('{p}') LIMIT 1").fetchone()
    cols=[d[0] for d in c.execute(f"DESCRIBE SELECT * FROM read_parquet('{p}')").fetchall()]
    print("\n",f)
    for col,val in zip(cols,row):
        print(col, repr(val)[:120])
