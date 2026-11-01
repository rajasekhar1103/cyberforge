from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import duckdb
import pandas as pd
import streamlit as st


DEFAULT_DATASET = os.environ.get(
    "CYBERFORGE_DETECTIONS_PATH",
    r"D:\cyberforge-run-20261101-0810\firex-detections.parquet",
)
PAGE_SIZES = (25, 50, 100)

st.set_page_config(
    page_title="CyberForge | Detection Results",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container { padding-top: 2rem; padding-bottom: 3rem; max-width: 1500px; }
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(28, 44, 66, .72), rgba(17, 26, 40, .72));
        border: 1px solid rgba(112, 145, 180, .2);
        border-radius: 12px;
        padding: 16px 18px;
    }
    [data-testid="stMetricLabel"] p { color: #9fb3c8; }
    .hero {
        border: 1px solid rgba(112, 145, 180, .22);
        border-radius: 16px;
        padding: 24px 28px;
        margin-bottom: 1.1rem;
        background: radial-gradient(ellipse at 82% 10%, rgba(35, 155, 150, .13), transparent 38%),
                    linear-gradient(120deg, #101b2a, #172438);
    }
    .eyebrow { color: #54d6c5; text-transform: uppercase; letter-spacing: .16em;
               font-size: .72rem; font-weight: 700; }
    .hero h1 { margin: .25rem 0 .2rem; font-size: 2.15rem; }
    .hero p { color: #9fb3c8; margin: 0; }
    </style>
    """,
    unsafe_allow_html=True,
)


def query_frame(path: str, query: str, parameters: list[Any] | None = None) -> pd.DataFrame:
    with duckdb.connect(":memory:") as connection:
        return connection.execute(query, [path, *(parameters or [])]).fetchdf()


@st.cache_data(show_spinner="Loading detection overview...")
def load_overview(path: str, file_size: int, modified_ns: int) -> dict[str, Any]:
    del file_size, modified_ns
    with duckdb.connect(":memory:") as connection:
        total = connection.execute(
            "SELECT count(*) FROM read_parquet(?)", [path]
        ).fetchone()[0]
        severities = connection.execute(
            """
            SELECT severity, count(*) AS detections
            FROM read_parquet(?)
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
            """,
            [path],
        ).fetchdf()
        rules = connection.execute(
            """
            SELECT rule_id, any_value(rule_name) AS rule_name,
                   any_value(severity) AS severity, count(*) AS detections
            FROM read_parquet(?)
            GROUP BY rule_id
            ORDER BY detections DESC, rule_id
            """,
            [path],
        ).fetchdf()
        timeline = connection.execute(
            """
            SELECT CAST("date" AS DATE) AS event_date, count(*) AS detections
            FROM read_parquet(?)
            WHERE "date" IS NOT NULL AND TRY_CAST("date" AS DATE) IS NOT NULL
            GROUP BY event_date
            ORDER BY event_date
            """,
            [path],
        ).fetchdf()
        categories = connection.execute(
            """
            SELECT category, count(*) AS detections
            FROM read_parquet(?)
            GROUP BY category
            ORDER BY detections DESC, category
            """,
            [path],
        ).fetchdf()
    return {
        "total": total,
        "severities": severities,
        "rules": rules,
        "timeline": timeline,
        "categories": categories,
    }


@st.cache_data(show_spinner=False)
def load_filter_options(path: str, file_size: int, modified_ns: int) -> dict[str, list[str]]:
    del file_size, modified_ns
    with duckdb.connect(":memory:") as connection:
        rules = connection.execute(
            "SELECT DISTINCT rule_id FROM read_parquet(?) ORDER BY rule_id", [path]
        ).fetchall()
        severities = connection.execute(
            "SELECT DISTINCT severity FROM read_parquet(?) ORDER BY severity", [path]
        ).fetchall()
    return {
        "rules": [row[0] for row in rules],
        "severities": [row[0] for row in severities],
    }


@st.cache_data(show_spinner="Finding source entities with multiple detection categories...")
def load_chain_sources(path: str, file_size: int, modified_ns: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    del file_size, modified_ns
    with duckdb.connect(":memory:") as connection:
        hot_times = connection.execute(
            """
            SELECT "date", "time", count(DISTINCT line_number) AS source_events
            FROM read_parquet(?)
            GROUP BY "date", "time"
            HAVING count(DISTINCT line_number) > 1000
            ORDER BY source_events DESC
            """,
            [path],
        ).fetchdf()
        sources = connection.execute(
            """
            WITH hot_times AS (
                SELECT "date", "time"
                FROM read_parquet(?)
                GROUP BY "date", "time"
                HAVING count(DISTINCT line_number) > 1000
            ),
            source_events AS (
                SELECT srcip, source_file, line_number, any_value(category) AS category,
                       max(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END)
                           AS high_severity
                FROM read_parquet(?) d
                WHERE srcip IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM hot_times h
                      WHERE h."date" = d."date" AND h."time" = d."time"
                  )
                GROUP BY srcip, source_file, line_number
            )
            SELECT srcip, count(DISTINCT category) AS categories,
                   count(*) FILTER (WHERE high_severity = 1) AS high_severity_events,
                   count(*) AS source_events
            FROM source_events
            GROUP BY srcip
            HAVING count(DISTINCT category) >= 2
               AND count(*) FILTER (WHERE high_severity = 1) >= 2
            ORDER BY categories DESC, high_severity_events DESC, srcip
            LIMIT 200
            """,
            [path, path],
        ).fetchdf()
        if not sources.empty:
            source_ids = sources["srcip"].tolist()
            placeholders = ", ".join("?" for _ in source_ids)
            source_events = connection.execute(
                f"""
                WITH hot_times AS (
                    SELECT "date", "time"
                    FROM read_parquet(?)
                    GROUP BY "date", "time"
                    HAVING count(DISTINCT line_number) > 1000
                )
                SELECT d.srcip, d.source_file, d.line_number,
                       min(TRY_CAST(d.eventtime AS HUGEINT)) AS eventtime,
                       any_value(d.category) AS category,
                       max(CASE WHEN d.severity IN ('high', 'critical') THEN 1 ELSE 0 END)
                           AS high_severity
                FROM read_parquet(?) d
                WHERE d.srcip IN ({placeholders})
                  AND TRY_CAST(d.eventtime AS HUGEINT) IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM hot_times h
                      WHERE h."date" = d."date" AND h."time" = d."time"
                  )
                GROUP BY d.srcip, d.source_file, d.line_number
                """,
                [path, path, *source_ids],
            ).fetchdf()

            source_quality = []
            window_ns = 10 * 60 * 1_000_000_000
            for srcip, group in source_events.groupby("srcip", sort=False):
                group = group.sort_values("eventtime").reset_index(drop=True)
                times = group["eventtime"].astype("int64").to_numpy()
                categories = group["category"].to_numpy()
                high_severity = group["high_severity"].to_numpy()
                best = (0, 0, 0, 0)
                for index, event_time in enumerate(times):
                    if not high_severity[index]:
                        continue
                    start = times.searchsorted(event_time - window_ns, side="left")
                    end = times.searchsorted(event_time + window_ns, side="right")
                    nearby_categories = len(set(categories[start:end]))
                    nearby_high = int(high_severity[start:end].sum())
                    nearby_count = end - start
                    span = int(times[end - 1] - times[start]) if nearby_count else 0
                    score = (nearby_categories, nearby_high, -span, -nearby_count)
                    if score > best:
                        best = score
                source_quality.append(
                    {
                        "srcip": srcip,
                        "path_categories": best[0],
                        "path_high_events": best[1],
                        "path_span": -best[2],
                        "path_events": -best[3],
                    }
                )
            sources = sources.merge(pd.DataFrame(source_quality), on="srcip")
            sources = sources.sort_values(
                ["path_categories", "path_high_events", "path_span", "path_events", "srcip"],
                ascending=[False, False, True, True, True],
            ).reset_index(drop=True)
    return hot_times, sources


@st.cache_data(show_spinner=False)
def load_chain_dates(
    path: str,
    file_size: int,
    modified_ns: int,
    srcip: str,
) -> pd.DataFrame:
    del file_size, modified_ns
    return query_frame(
        path,
        """
        WITH hot_times AS (
            SELECT "date", "time"
            FROM read_parquet(?)
            GROUP BY "date", "time"
            HAVING count(DISTINCT line_number) > 1000
        )
        SELECT d."date", count(DISTINCT d.line_number) AS source_events,
               count(DISTINCT d.category) AS categories,
               count(DISTINCT d.line_number) FILTER (
                   WHERE d.severity IN ('high', 'critical')
               ) AS high_severity_events
        FROM read_parquet(?) d
        WHERE d.srcip = ?
          AND NOT EXISTS (
              SELECT 1 FROM hot_times h
              WHERE h."date" = d."date" AND h."time" = d."time"
          )
        GROUP BY d."date"
        ORDER BY categories DESC, high_severity_events DESC, d."date" DESC
        """,
        [path, srcip],
    )


@st.cache_data(show_spinner=False)
def load_chain_anchors(
    path: str,
    file_size: int,
    modified_ns: int,
    srcip: str,
    date: str,
) -> pd.DataFrame:
    del file_size, modified_ns
    return query_frame(
        path,
        """
        WITH hot_times AS (
            SELECT "date", "time"
            FROM read_parquet(?)
            GROUP BY "date", "time"
            HAVING count(DISTINCT line_number) > 1000
        )
        SELECT d.source_file, d.line_number, d.srcip,
               min(d."date") AS "date", min(d."time") AS "time",
               min(TRY_CAST(d.eventtime AS HUGEINT)) AS eventtime,
               any_value(d.dstip) AS dstip, any_value(d.category) AS category,
               string_agg(DISTINCT d.rule_id, ' + ' ORDER BY d.rule_id) AS rule_ids,
               max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                   WHEN 'medium' THEN 2 ELSE 1 END) AS severity_rank,
               arg_max(d.severity, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                   WHEN 'medium' THEN 2 ELSE 1 END) AS severity,
               coalesce(arg_max(d.confidence, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                               WHEN 'medium' THEN 2 ELSE 1 END),
                        'unvalidated') AS rule_confidence,
               arg_max(d.rule_name, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                    WHEN 'medium' THEN 2 ELSE 1 END) AS rule_name,
               arg_max(d.description, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                       WHEN 'medium' THEN 2 ELSE 1 END) AS description,
               arg_max(d.evidence, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                   WHEN 'medium' THEN 2 ELSE 1 END) AS evidence
        FROM read_parquet(?) d
        WHERE d.srcip = ? AND d."date" = ?
          AND TRY_CAST(d.eventtime AS HUGEINT) IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM hot_times h
              WHERE h."date" = d."date" AND h."time" = d."time"
          )
        GROUP BY d.source_file, d.line_number, d.srcip
        ORDER BY eventtime, d.line_number
        """,
        [path, srcip, date],
    )


def rank_chain_anchors(events: pd.DataFrame, window_minutes: int) -> pd.DataFrame:
    severe = events.loc[events["severity_rank"] >= 3].copy()
    if severe.empty:
        return severe

    times = events["eventtime"].astype("int64")
    window_ns = window_minutes * 60 * 1_000_000_000
    event_counts: list[int] = []
    category_counts: list[int] = []
    high_counts: list[int] = []
    spans: list[int] = []
    for anchor_time in severe["eventtime"].astype("int64"):
        nearby = events.loc[(times - anchor_time).abs() <= window_ns]
        event_counts.append(len(nearby))
        category_counts.append(int(nearby["category"].nunique()))
        high_counts.append(int((nearby["severity_rank"] >= 3).sum()))
        nearby_times = nearby["eventtime"].astype("int64")
        spans.append(int(nearby_times.max() - nearby_times.min()) if len(nearby) else 0)

    severe["nearby_events"] = event_counts
    severe["nearby_categories"] = category_counts
    severe["nearby_high_events"] = high_counts
    severe["nearby_span"] = spans
    severe = severe.sort_values(
        [
            "nearby_categories",
            "nearby_high_events",
            "nearby_span",
            "nearby_events",
            "severity_rank",
            "eventtime",
        ],
        ascending=[False, False, True, True, False, True],
    )
    return severe.head(200).reset_index(drop=True)


@st.cache_data(show_spinner=False)
def load_chain_context(
    path: str,
    file_size: int,
    modified_ns: int,
    anchor: dict[str, Any],
    window_minutes: int,
) -> pd.DataFrame:
    del file_size, modified_ns
    anchor_time = int(anchor["eventtime"])
    window_ns = window_minutes * 60 * 1_000_000_000
    return query_frame(
        path,
        """
        WITH hot_times AS (
            SELECT "date", "time"
            FROM read_parquet(?)
            GROUP BY "date", "time"
            HAVING count(DISTINCT line_number) > 1000
        ),
        source_events AS (
            SELECT d.source_file, d.line_number, d.srcip,
                   min(d."date") AS "date", min(d."time") AS "time",
                   min(TRY_CAST(d.eventtime AS HUGEINT)) AS eventtime,
                   any_value(d.dstip) AS dstip, any_value(d.category) AS category,
                   string_agg(DISTINCT d.rule_id, ' + ' ORDER BY d.rule_id) AS rule_ids,
                   max(CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                       WHEN 'medium' THEN 2 ELSE 1 END) AS severity_rank,
                   arg_max(d.severity, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                       WHEN 'medium' THEN 2 ELSE 1 END) AS severity,
                   coalesce(arg_max(d.confidence, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                                   WHEN 'medium' THEN 2 ELSE 1 END),
                            'unvalidated') AS rule_confidence,
                   arg_max(d.description, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                          WHEN 'medium' THEN 2 ELSE 1 END) AS description,
                   arg_max(d.evidence, CASE d.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                                                       WHEN 'medium' THEN 2 ELSE 1 END) AS evidence
            FROM read_parquet(?) d
            WHERE d.srcip = ?
              AND TRY_CAST(d.eventtime AS HUGEINT) BETWEEN ? AND ?
              AND NOT EXISTS (
                  SELECT 1 FROM hot_times h
                  WHERE h."date" = d."date" AND h."time" = d."time"
              )
            GROUP BY d.source_file, d.line_number, d.srcip
        )
        SELECT * FROM source_events
        ORDER BY eventtime, line_number
        """,
        [path, anchor["srcip"], anchor_time - window_ns, anchor_time + window_ns],
    )


def graph_label(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def evidence_summary(evidence: str) -> str:
    fields = json.loads(evidence)
    labels = {
        "attack": "signature",
        "virus": "malware",
        "hostname": "host",
        "catdesc": "web category",
        "action": "action",
        "status": "status",
        "user": "user",
        "reason": "reason",
    }
    values = [
        f"{label}: {fields[key]}"
        for key, label in labels.items()
        if fields.get(key) not in (None, "")
    ]
    summary = " · ".join(values)
    return summary[:100] + ("…" if len(summary) > 100 else "")


def activity_path_dot(srcip: str, events: pd.DataFrame) -> str:
    lines = [
        "digraph activity_path {",
        '  graph [rankdir=TB, bgcolor="transparent", pad="0.3", nodesep="0.4", ranksep="0.55"];',
        '  node [shape=box, style="rounded,filled", fontname="Segoe UI", fontsize=11, color="#475569", fontcolor="#0f172a", margin="0.16,0.10"];',
        '  edge [fontname="Segoe UI", fontsize=9, color="#64748b", fontcolor="#475569", arrowsize=0.7];',
        f"  source [shape=ellipse, label={graph_label('SOURCE IP\n' + srcip)}, fillcolor=\"#dbeafe\"];",
    ]
    for position, (_, event) in enumerate(events.iterrows()):
        event_node = f"event_{position}"
        destination_node = f"destination_{position}"
        event_title = (
            f"{event['date']} {event['time']}\n"
            f"{str(event['severity']).upper()} · {event['rule_ids']}\n"
            f"{event['category']}\n"
            f"rule confidence: {event['rule_confidence']}\n"
            f"{evidence_summary(event['evidence'])}\n"
            f"{event['description']}\n"
            f"source line {event['line_number']}"
        )
        lines.append(
            f"  {event_node} [label={graph_label(event_title)}, fillcolor=\"#fef3c7\"];"
        )
        lines.append(
            f"  source -> {event_node} [label=\"observed source\"];"
        )
        if pd.notna(event["dstip"]):
            destination = str(event["dstip"])
            lines.append(
                f"  {destination_node} [label={graph_label('DESTINATION IP\n' + destination)}, "
                'fillcolor="#dcfce7"];'
            )
            lines.append(
                f"  {event_node} -> {destination_node} [label=\"observed destination\"];"
            )
            lines.append(
                f"  {{ rank=same; {event_node}; {destination_node}; }}"
            )
        if position:
            previous_node = f"event_{position - 1}"
            lines.append(
                f"  {previous_node} -> {event_node} "
                '[style=dashed, color="#d97706", label="same source · time order only"];'
            )
    lines.append("}")
    return "\n".join(lines)


def load_page(
    path: str,
    filters: dict[str, Any],
    limit: int,
    offset: int,
) -> tuple[int, pd.DataFrame]:
    clauses = []
    parameters: list[Any] = []
    if filters["severities"]:
        clauses.append(f"severity IN ({', '.join('?' for _ in filters['severities'])})")
        parameters.extend(filters["severities"])
    if filters["rules"]:
        clauses.append(f"rule_id IN ({', '.join('?' for _ in filters['rules'])})")
        parameters.extend(filters["rules"])
    for column, key in (("srcip", "srcip"), ("username", "username")):
        value = filters[key].strip()
        if value:
            clauses.append(f"lower(coalesce({column}, '')) LIKE ?")
            parameters.append(f"%{value.lower()}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    with duckdb.connect(":memory:") as connection:
        total = connection.execute(
            f"SELECT count(*) FROM read_parquet(?) {where}",
            [path, *parameters],
        ).fetchone()[0]
        frame = connection.execute(
            f"""
            SELECT date, time, severity, rule_id, rule_name, category,
                   srcip, dstip, username, host, description, detection_id
            FROM read_parquet(?) {where}
            ORDER BY CASE severity
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                date DESC NULLS LAST, time DESC NULLS LAST
            LIMIT ? OFFSET ?
            """,
            [path, *parameters, limit, offset],
        ).fetchdf()
    return total, frame


st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">CyberForge · Threat detection</div>
      <h1>Detection results</h1>
      <p>Explore severity, detection rules, event timeline, and individual findings.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Detection dataset")
    dataset_path = st.text_input("Parquet file", value=DEFAULT_DATASET).strip().strip('"')
    if st.button("Refresh data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

try:
    dataset = Path(dataset_path).expanduser().resolve(strict=True)
    if not dataset.is_file() or dataset.suffix.lower() != ".parquet":
        raise ValueError("Select an existing .parquet detection file.")
    stat = dataset.stat()
    overview = load_overview(str(dataset), stat.st_size, stat.st_mtime_ns)
    options = load_filter_options(str(dataset), stat.st_size, stat.st_mtime_ns)
except (OSError, ValueError, duckdb.Error) as exc:
    st.error(f"Could not load detection dataset: {exc}")
    st.stop()

metric_columns = st.columns(4)
metric_columns[0].metric("Total detections", f"{overview['total']:,}")
for index, severity in enumerate(("critical", "high", "medium"), start=1):
    severity_rows = overview["severities"]
    found = severity_rows.loc[severity_rows["severity"] == severity, "detections"]
    count = int(found.iloc[0]) if not found.empty else 0
    metric_columns[index].metric(f"{severity.title()} severity", f"{count:,}")

overview_tab, findings_tab, path_tab = st.tabs(["Overview", "Findings", "Activity path"])
with overview_tab:
    left, right = st.columns(2)
    with left:
        st.markdown("#### Detections by severity")
        st.bar_chart(overview["severities"].set_index("severity")[["detections"]])
        st.markdown("#### Detections over time")
        if overview["timeline"].empty:
            st.info("No usable date values were found in this dataset.")
        else:
            st.line_chart(overview["timeline"].set_index("event_date")[["detections"]])
    with right:
        st.markdown("#### Detections by rule")
        rule_chart = overview["rules"].copy()
        rule_chart["rule"] = rule_chart["rule_id"] + " · " + rule_chart["rule_name"]
        st.bar_chart(rule_chart.set_index("rule")[["detections"]])
        st.markdown("#### Detections by category")
        st.bar_chart(overview["categories"].set_index("category")[["detections"]])
    st.dataframe(
        overview["rules"],
        width="stretch",
        hide_index=True,
        column_config={
            "detections": st.column_config.NumberColumn(format="%d"),
        },
    )
    st.caption(f"Dataset: `{dataset}`")

with findings_tab:
    with st.sidebar.form("detection_filter_form"):
        st.markdown("#### Finding filters")
        selected_severities = st.multiselect(
            "Severity",
            options["severities"],
            default=options["severities"],
        )
        selected_rules = st.multiselect(
            "Rule",
            options["rules"],
            default=options["rules"],
        )
        source_ip = st.text_input("Source IP contains")
        username = st.text_input("Username contains")
        page_size = st.selectbox("Rows per page", PAGE_SIZES, index=0)
        apply_filters = st.form_submit_button("Apply filters", type="primary")
    if apply_filters or "applied_detection_filters" not in st.session_state:
        st.session_state.applied_detection_filters = {
            "severities": selected_severities,
            "rules": selected_rules,
            "srcip": source_ip,
            "username": username,
        }
        st.session_state.detection_offset = 0
        st.session_state.detection_page_size = page_size

    filters = st.session_state.applied_detection_filters
    page_size = st.session_state.detection_page_size
    try:
        matching_total, findings = load_page(
            str(dataset),
            filters,
            page_size,
            st.session_state.detection_offset,
        )
    except duckdb.Error as exc:
        st.error(f"Could not query detections: {exc}")
    else:
        st.caption(f"{matching_total:,} matching detections")
        st.dataframe(
            findings,
            width="stretch",
            hide_index=True,
            column_config={
                "detection_id": st.column_config.TextColumn("Detection ID"),
                "severity": st.column_config.TextColumn("Severity"),
                "description": st.column_config.TextColumn("Description", width="large"),
            },
        )
        previous, page_label, next_page = st.columns([1, 2, 1])
        offset = st.session_state.detection_offset
        total_pages = max(1, (matching_total + page_size - 1) // page_size)
        with previous:
            if st.button(
                "← Previous",
                disabled=offset == 0,
                use_container_width=True,
                key="detection_previous",
            ):
                st.session_state.detection_offset = max(0, offset - page_size)
                st.rerun()
        with page_label:
            page_number = offset // page_size + 1
            st.markdown(
                f"<div style='text-align:center;padding:.5rem'>"
                f"Page {page_number} of {total_pages}</div>",
                unsafe_allow_html=True,
            )
        with next_page:
            if st.button(
                "Next →",
                disabled=offset + page_size >= matching_total,
                use_container_width=True,
                key="detection_next",
            ):
                st.session_state.detection_offset += page_size
                st.rerun()

with path_tab:
    st.markdown("#### Evidence-linked activity path")
    st.caption(
        "Start from a high-severity finding and inspect nearby records from the same source IP. "
        "Duplicate rule hits on one source line are merged; the graph is capped to six events. "
        "The source selector shows up to 200 multi-category candidates."
    )
    if not options["rules"]:
        st.info("No detection records are available to build an activity path.")
    else:
        try:
            hot_times, source_options = load_chain_sources(
                str(dataset), stat.st_size, stat.st_mtime_ns
            )
        except duckdb.Error as exc:
            st.error(f"Could not prepare activity-path candidates: {exc}")
        else:
            if not hot_times.empty:
                hot_row = hot_times.iloc[0]
                st.warning(
                    f"Excluded {int(hot_row['source_events']):,} source events at the repeated "
                    f"timestamp {hot_row['date']} {hot_row['time']} from path selection. "
                    "That timestamp burst would dominate temporal correlation."
                )
            if source_options.empty:
                st.info(
                    "No source IP has at least two high-severity events across multiple "
                    "detection categories outside the repeated-timestamp burst."
                )
            else:
                source_choices = source_options["srcip"].tolist()
                selected_source = st.selectbox(
                    "Source IP with cross-category evidence",
                    source_choices,
                    format_func=lambda value: (
                        f"{value} · "
                        f"{int(source_options.loc[source_options['srcip'] == value, 'categories'].iloc[0])} "
                        "categories · "
                        f"{int(source_options.loc[source_options['srcip'] == value, 'path_categories'].iloc[0])} "
                        "near anchor"
                    ),
                    key="path_source",
                )
                dates = load_chain_dates(
                    str(dataset), stat.st_size, stat.st_mtime_ns, selected_source
                )
                if dates.empty:
                    st.info("No dates are available for this source after data-quality filtering.")
                else:
                    selected_date = st.selectbox(
                        "Date",
                        dates["date"].tolist(),
                        key="path_date",
                    )
                    window_minutes = st.select_slider(
                        "Nearby-event window (minutes, each side)",
                        options=[5, 10, 15],
                        value=10,
                        key="path_window",
                    )
                    anchors = load_chain_anchors(
                        str(dataset),
                        stat.st_size,
                        stat.st_mtime_ns,
                        selected_source,
                        selected_date,
                    )
                    anchors = rank_chain_anchors(anchors, window_minutes)
                    if anchors.empty:
                        st.info(
                            "No high/critical anchor findings exist for this source and date."
                        )
                    else:
                        anchor_line = st.selectbox(
                            "Anchor finding",
                            anchors["line_number"].tolist(),
                            format_func=lambda line_number: (
                                f"{anchors.loc[anchors['line_number'] == line_number, 'time'].iloc[0]} · "
                                f"{str(anchors.loc[anchors['line_number'] == line_number, 'severity'].iloc[0]).upper()} · "
                                f"{anchors.loc[anchors['line_number'] == line_number, 'rule_ids'].iloc[0]} · "
                                f"{anchors.loc[anchors['line_number'] == line_number, 'description'].iloc[0]} · "
                                f"{int(anchors.loc[anchors['line_number'] == line_number, 'nearby_categories'].iloc[0])} categories/"
                                f"{int(anchors.loc[anchors['line_number'] == line_number, 'nearby_events'].iloc[0])} nearby events · "
                                f"line {line_number}"
                            ),
                            key=f"path_anchor_line_{selected_source}_{selected_date}_{window_minutes}",
                        )
                        anchor = anchors.loc[
                            anchors["line_number"] == anchor_line
                        ].iloc[0].to_dict()
                        try:
                            path_events = load_chain_context(
                                str(dataset),
                                stat.st_size,
                                stat.st_mtime_ns,
                                anchor,
                                window_minutes,
                            )
                        except duckdb.Error as exc:
                            st.error(f"Could not load nearby source events: {exc}")
                        else:
                            if len(path_events) > 6:
                                anchor_line = int(anchor["line_number"])
                                path_events["anchor_distance"] = (
                                    path_events["eventtime"].astype("int64")
                                    - int(anchor["eventtime"])
                                ).abs()
                                path_events["is_anchor"] = (
                                    path_events["line_number"] == anchor_line
                                )
                                path_events = (
                                    path_events.sort_values(
                                        ["is_anchor", "anchor_distance"],
                                        ascending=[False, True],
                                    )
                                    .head(6)
                                    .sort_values(["eventtime", "line_number"])
                                    .drop(columns=["anchor_distance", "is_anchor"])
                                )
                            metric_columns = st.columns(3)
                            metric_columns[0].metric("Source events", len(path_events))
                            metric_columns[1].metric(
                                "Detection categories", path_events["category"].nunique()
                            )
                            metric_columns[2].metric(
                                "High/critical events",
                                int((path_events["severity_rank"] >= 3).sum()),
                            )
                            if path_events.empty:
                                st.info("No nearby source events were found.")
                            else:
                                st.graphviz_chart(
                                    activity_path_dot(selected_source, path_events),
                                    width="stretch",
                                )
                                st.info(
                                    "**Evidence semantics:** solid edges are source/destination "
                                    "fields recorded on the detection. Rule confidence describes "
                                    "the detector match, not proof of compromise. Dashed edges mean only "
                                    "chronological order for the same source IP within the chosen "
                                    "window; they do not prove causation, compromise, or a kill-chain stage."
                                )
                                st.dataframe(
                                    path_events[
                                        [
                                            "date",
                                            "time",
                                            "severity",
                                            "category",
                                            "rule_ids",
                                            "rule_confidence",
                                            "description",
                                            "srcip",
                                            "dstip",
                                            "evidence",
                                            "source_file",
                                            "line_number",
                                        ]
                                    ],
                                    width="stretch",
                                    hide_index=True,
                                    column_config={
                                        "evidence": st.column_config.TextColumn(
                                            "Evidence fields", width="large"
                                        ),
                                        "description": st.column_config.TextColumn(
                                            "Detection", width="large"
                                        ),
                                    },
                                )
                                st.caption(
                                    "Use the source file and line number to validate each item "
                                    "against the original log. Detection rule labels are analytical "
                                    "matches, not independent confirmation that the behavior succeeded."
                                )
