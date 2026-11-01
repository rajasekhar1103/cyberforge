from __future__ import annotations

import os
from typing import Any

import pandas as pd
import requests
import streamlit as st


DEFAULT_API_URL = os.environ.get("CYBERFORGE_API_URL", "http://127.0.0.1:8000").rstrip("/")
SEVERITIES = ("low", "medium", "high", "critical")
NODE_TYPES = ("ip", "user", "host", "technique", "detection", "incident")

st.set_page_config(
    page_title="CyberForge | Investigation",
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


def api_get(base_url: str, path: str, params: dict[str, Any] | None = None) -> Any:
    response = requests.get(
        f"{base_url}{path}",
        params=params,
        timeout=(3.05, 35),
    )
    try:
        body = response.json()
    except requests.exceptions.JSONDecodeError as exc:
        raise RuntimeError(f"API returned non-JSON data (HTTP {response.status_code})") from exc
    if not response.ok:
        error = body.get("error", {}) if isinstance(body, dict) else {}
        message = error.get("message", f"API request failed with HTTP {response.status_code}")
        details = error.get("details")
        if details:
            message = f"{message} — {details}"
        raise RuntimeError(message)
    return body


def dataframe_rows(rows: list[dict[str, Any]]) -> pd.DataFrame:
    if not rows:
        return pd.DataFrame()
    normalized = []
    for row in rows:
        normalized.append(
            {
                key: value if isinstance(value, (str, int, float, bool)) or value is None
                else str(value)
                for key, value in row.items()
            }
        )
    return pd.DataFrame(normalized)


def pretty_severity_counts(counts: dict[str, int]) -> dict[str, int]:
    return {severity.title(): counts.get(severity, 0) for severity in SEVERITIES}


def render_incident_detail(base_url: str, incident_id: str) -> None:
    st.markdown(f"#### Observation cluster `{incident_id}`")
    try:
        detail = api_get(
            base_url,
            f"/api/incidents/{incident_id}",
            {"limit": 100, "offset": 0},
        )
        incident = detail["incident"]
    except (requests.RequestException, RuntimeError, KeyError) as exc:
        st.error(f"Could not load incident detail: {exc}")
        return

    left, right = st.columns([1.5, 1])
    with left:
        st.markdown(f"**{incident.get('title', 'Observation cluster')}**")
        st.write(incident.get("description", ""))
        st.caption(
            f"Severity: {incident.get('severity', 'unknown')} · "
            f"Confidence: {incident.get('confidence') or 'unvalidated'} · "
            f"Status: {incident.get('status', 'unknown')}"
        )
    with right:
        st.metric("Linked detections", incident.get("detection_count", 0))
        st.caption(
            f"First observed: {incident.get('first_observed') or '—'}  \n"
            f"Last observed: {incident.get('last_observed') or '—'}"
        )

    with st.expander("Incident fields and evidence", expanded=False):
        st.json(incident)

    detections = detail.get("detections", [])
    st.markdown("##### Linked detections")
    st.dataframe(
        dataframe_rows(detections),
        use_container_width=True,
        hide_index=True,
    )
    if detail.get("detections_pagination", {}).get("total", 0) > len(detections):
        st.caption("Showing the first 100 linked detections. Use the incident API cursor for deeper pages.")

    timeline_tab, graph_tab = st.tabs(["Timeline", "Relationship graph"])
    with timeline_tab:
        try:
            timeline = api_get(
                base_url,
                f"/api/incidents/{incident_id}/timeline",
                {"limit": 500, "offset": 0},
            )
            st.dataframe(
                dataframe_rows(timeline.get("items", [])),
                use_container_width=True,
                hide_index=True,
            )
            if timeline.get("pagination", {}).get("total", 0) > len(timeline.get("items", [])):
                st.caption("Showing the first 500 timeline items.")
        except (requests.RequestException, RuntimeError) as exc:
            st.error(f"Could not load timeline: {exc}")

    with graph_tab:
        graph_options, graph_refresh = st.columns([3, 1])
        with graph_options:
            depth = st.select_slider("Traversal depth", options=[1, 2, 3], value=1, key="graph_depth")
            include_derived = st.toggle("Include derived relationships", value=True, key="graph_derived")
            selected_node_types = st.multiselect(
                "Node types",
                NODE_TYPES,
                default=list(NODE_TYPES),
                key="graph_node_types",
            )
        with graph_refresh:
            st.markdown("<br>", unsafe_allow_html=True)
            load_graph = st.button("Load graph", type="primary", key="load_graph")
        graph_params: list[tuple[str, Any]] = [
            ("depth", depth),
            ("include_derived", str(include_derived).lower()),
            ("max_nodes", 1000),
        ]
        graph_params.extend(("node_type", node_type) for node_type in selected_node_types)
        load_graph = load_graph or "graph_data" not in st.session_state
        if load_graph:
            try:
                st.session_state.graph_data = api_get(
                    base_url,
                    f"/api/incidents/{incident_id}/graph",
                    graph_params,
                )
                st.session_state.graph_for_incident = incident_id
            except (requests.RequestException, RuntimeError) as exc:
                st.error(f"Could not load graph: {exc}")
        graph = st.session_state.get("graph_data")
        if graph and st.session_state.get("graph_for_incident") == incident_id:
            nodes = graph.get("nodes", [])
            edges = graph.get("edges", [])
            graph_col1, graph_col2 = st.columns(2)
            graph_col1.metric("Nodes", len(nodes))
            graph_col2.metric("Relationships", len(edges))
            st.caption(
                "The `observed` flag is preserved. Technique mapping and incident links marked "
                "`observed=false` are derived relationships, not observed evidence."
            )
            nodes_tab, edges_tab = st.tabs(["Nodes", "Edges"])
            with nodes_tab:
                st.dataframe(dataframe_rows(nodes), use_container_width=True, hide_index=True)
            with edges_tab:
                st.dataframe(dataframe_rows(edges), use_container_width=True, hide_index=True)


st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">CyberForge · Threat investigation</div>
      <h1>Investigation workspace</h1>
      <p>Explore correlated incidents, source detections, timelines, and graph relationships.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Workspace")
    api_base_url = st.text_input("Investigation API", value=DEFAULT_API_URL).strip().rstrip("/")
    if st.button("Refresh data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    st.divider()
    with st.form("incident_filters"):
        st.markdown("#### Incident filters")
        severity_choice = st.selectbox("Severity", ["All", *[value.title() for value in SEVERITIES]])
        source_ip = st.text_input("Source IP")
        username = st.text_input("Username")
        page_size = st.select_slider("Rows per page", options=[10, 25, 50, 100], value=25)
        applied = st.form_submit_button("Apply filters", type="primary", use_container_width=True)
    if applied or "applied_incident_filters" not in st.session_state:
        st.session_state.applied_incident_filters = {
            "severity": None if severity_choice == "All" else severity_choice.lower(),
            "srcip": source_ip.strip() or None,
            "username": username.strip() or None,
            "limit": page_size,
        }
        st.session_state.incident_offset = 0
    if "incident_offset" not in st.session_state:
        st.session_state.incident_offset = 0

try:
    health = api_get(api_base_url, "/api/health")
    summary = api_get(api_base_url, "/api/summary")
except (requests.RequestException, RuntimeError) as exc:
    st.error(
        f"Cannot reach the investigation API at `{api_base_url}`. "
        "Start the API and confirm its configured stores are ready."
    )
    st.code(str(exc))
    st.stop()

stores = health.get("stores", {})
not_ready = [name for name, status in stores.items() if status != "ready"]
if not_ready:
    st.warning(f"Some analytics stores are not ready: {', '.join(not_ready)}")
else:
    st.success("All configured analytics stores are ready.")

metric_columns = st.columns(4)
metric_columns[0].metric("Incidents", f"{summary['total_incidents']:,}")
metric_columns[1].metric("Detections", f"{summary['total_detections']:,}")
metric_columns[2].metric("Unassigned detections", f"{summary['unassigned_detections']:,}")
metric_columns[3].metric(
    "Technique IDs",
    f"{api_get(api_base_url, '/api/techniques', {'limit': 1})['pagination']['total']:,}",
)

overview_tab, incidents_tab, techniques_tab, detection_tab = st.tabs(
    ["Overview", "Incidents", "Techniques", "Detection lookup"]
)

with overview_tab:
    chart_left, chart_right = st.columns(2)
    with chart_left:
        st.markdown("#### Incidents by severity")
        st.bar_chart(pd.Series(pretty_severity_counts(summary["incidents_by_severity"]), name="Incidents"))
    with chart_right:
        st.markdown("#### Detections by category")
        category_counts = summary.get("detections_by_category", {})
        st.bar_chart(pd.Series(category_counts, name="Detections").sort_values(ascending=False))
    st.caption(
        f"Snapshot summary · {summary['total_incidents']:,} incidents · "
        f"{summary['total_detections']:,} detections"
    )

with incidents_tab:
    filters = st.session_state.applied_incident_filters
    query: dict[str, Any] = {
        "limit": filters["limit"],
        "offset": st.session_state.incident_offset,
    }
    for name in ("severity", "srcip", "username"):
        if filters[name] is not None:
            query[name] = filters[name]
    try:
        incident_page = api_get(api_base_url, "/api/incidents", query)
    except (requests.RequestException, RuntimeError) as exc:
        st.error(f"Could not load incidents: {exc}")
    else:
        page = incident_page["pagination"]
        st.caption(f"{page['total']:,} matching incidents")
        st.dataframe(
            dataframe_rows(incident_page.get("items", [])),
            use_container_width=True,
            hide_index=True,
        )
        previous, page_label, next_page = st.columns([1, 2, 1])
        with previous:
            if st.button(
                "← Previous",
                disabled=st.session_state.incident_offset == 0,
                use_container_width=True,
            ):
                st.session_state.incident_offset = max(
                    0,
                    st.session_state.incident_offset - filters["limit"],
                )
                st.rerun()
        with page_label:
            page_number = st.session_state.incident_offset // filters["limit"] + 1
            total_pages = max(1, (page["total"] + filters["limit"] - 1) // filters["limit"])
            st.markdown(
                f"<div style='text-align:center;padding:.5rem'>Page {page_number} of {total_pages}</div>",
                unsafe_allow_html=True,
            )
        with next_page:
            has_next = st.session_state.incident_offset + filters["limit"] < page["total"]
            if st.button("Next →", disabled=not has_next, use_container_width=True):
                st.session_state.incident_offset += filters["limit"]
                st.rerun()

        incident_options = [
            f"{item['incident_id']} · {item['severity']} · {item['title']}"
            for item in incident_page.get("items", [])
        ]
        if incident_options:
            selected_option = st.selectbox("Open incident", incident_options)
            selected_incident_id = selected_option.split(" · ", 1)[0]
            render_incident_detail(api_base_url, selected_incident_id)
        else:
            st.info("No incidents match the selected filters.")

with techniques_tab:
    st.markdown("#### Technique coverage")
    try:
        technique_data = api_get(api_base_url, "/api/techniques", {"limit": 200})
        st.dataframe(
            dataframe_rows(technique_data.get("items", [])),
            use_container_width=True,
            hide_index=True,
        )
        st.caption("Technique names and tactics are not provided because the configured API has no catalog.")
    except (requests.RequestException, RuntimeError) as exc:
        st.error(f"Could not load techniques: {exc}")

with detection_tab:
    st.markdown("#### Find a detection")
    with st.form("detection_lookup"):
        detection_id = st.text_input("Detection UUID")
        lookup_detection = st.form_submit_button("Look up detection", type="primary")
    if lookup_detection:
        try:
            st.session_state.detection_result = api_get(
                api_base_url,
                f"/api/detections/{detection_id.strip()}",
            )
        except (requests.RequestException, RuntimeError) as exc:
            st.error(f"Could not load detection: {exc}")
            st.session_state.pop("detection_result", None)
    if "detection_result" in st.session_state:
        detection = st.session_state.detection_result
        st.json(detection)
        techniques = detection.get("mitre_techniques") or []
        if techniques:
            st.caption(
                "Mapped technique IDs: "
                + ", ".join(techniques)
                + ". These mappings are analytical classifications, not source-record proof."
            )
