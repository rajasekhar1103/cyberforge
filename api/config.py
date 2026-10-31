from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path


_MEMORY_LIMIT = re.compile(r"^[1-9][0-9]*(?:KB|MB|GB|TB)$", re.IGNORECASE)


@dataclass(frozen=True)
class ApiConfig:
    detections_path: Path
    incidents_path: Path
    incident_detections_path: Path
    graph_path: Path
    duckdb_memory_limit: str = "256MB"
    duckdb_threads: int = 2
    max_concurrent_queries: int = 1
    query_timeout_seconds: float = 30.0
    duckdb_temp_directory: Path = Path(tempfile.gettempdir()) / "cyberforge-api-duckdb"
    max_graph_file_bytes: int = 64 * 1024 * 1024
    max_graph_edges: int = 20_000
    max_response_bytes: int = 4 * 1024 * 1024

    def __post_init__(self) -> None:
        if not _MEMORY_LIMIT.fullmatch(self.duckdb_memory_limit):
            raise ValueError("duckdb_memory_limit must be a positive value with a KB, MB, GB, or TB unit")
        if not 1 <= self.duckdb_threads <= 8:
            raise ValueError("duckdb_threads must be between 1 and 8")
        if not 1 <= self.max_concurrent_queries <= 16:
            raise ValueError("max_concurrent_queries must be between 1 and 16")
        if self.query_timeout_seconds <= 0:
            raise ValueError("query_timeout_seconds must be positive")
        if self.max_graph_file_bytes <= 0 or self.max_graph_edges <= 0 or self.max_response_bytes <= 0:
            raise ValueError("graph and response limits must be positive")

    @classmethod
    def from_env(cls) -> ApiConfig:
        data_dir = Path(os.environ.get("CYBERFORGE_DATA_DIR", "data/analytics")).resolve()
        temp_dir = Path(
            os.environ.get(
                "CYBERFORGE_DUCKDB_TEMP_DIR",
                str(Path(tempfile.gettempdir()) / "cyberforge-api-duckdb"),
            )
        ).resolve()
        return cls(
            detections_path=Path(
                os.environ.get("CYBERFORGE_DETECTIONS_PATH", str(data_dir / "detections.parquet"))
            ).resolve(),
            incidents_path=Path(
                os.environ.get("CYBERFORGE_INCIDENTS_PATH", str(data_dir / "incidents.parquet"))
            ).resolve(),
            incident_detections_path=Path(
                os.environ.get(
                    "CYBERFORGE_INCIDENT_DETECTIONS_PATH",
                    str(data_dir / "incident_detections.parquet"),
                )
            ).resolve(),
            graph_path=Path(os.environ.get("CYBERFORGE_GRAPH_PATH", str(data_dir / "graph.json"))).resolve(),
            duckdb_memory_limit=os.environ.get("CYBERFORGE_DUCKDB_MEMORY_LIMIT", "256MB"),
            duckdb_threads=int(os.environ.get("CYBERFORGE_DUCKDB_THREADS", "2")),
            max_concurrent_queries=int(os.environ.get("CYBERFORGE_MAX_CONCURRENT_QUERIES", "1")),
            query_timeout_seconds=float(os.environ.get("CYBERFORGE_QUERY_TIMEOUT_SECONDS", "30")),
            duckdb_temp_directory=temp_dir,
            max_graph_file_bytes=int(os.environ.get("CYBERFORGE_MAX_GRAPH_FILE_BYTES", str(64 * 1024 * 1024))),
            max_graph_edges=int(os.environ.get("CYBERFORGE_MAX_GRAPH_EDGES", "20000")),
            max_response_bytes=int(os.environ.get("CYBERFORGE_MAX_RESPONSE_BYTES", str(4 * 1024 * 1024))),
        )
