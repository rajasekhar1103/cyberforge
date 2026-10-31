import json, subprocess, os, tempfile, shutil
import pyarrow.parquet as pq
from engine import run, load_rules

def make_parquet(rows):
    import pyarrow as pa
    schema = pa.schema([...]) if False else None
