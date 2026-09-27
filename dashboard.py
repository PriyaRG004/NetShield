import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# ==========================================================
# PAGE CONFIGURATION
# ==========================================================

st.set_page_config(
    page_title="NetShield SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DATABASE_FILE = "netshield.db"

# Refresh every 5 seconds
st_autorefresh(interval=5000, key="netshield_refresh")


# ==========================================================
# DATABASE
# ==========================================================

@st.cache_data(ttl=5)
def get_alerts():
    connection = sqlite3.connect(DATABASE_FILE)

    query = """
        SELECT
            id,
            timestamp,
            alert_type,
            severity,
            source_ip,
            destination_ip,
            unique_ports,
            time_window,
            detection,
            attempts
        FROM alerts
        ORDER BY id DESC
    """

    try:
        dataframe = pd.read_sql_query(query, connection)
    finally:
        connection.close()

    return dataframe


alerts = get_alerts()


# ==========================================================
# METRICS
# ==========================================================

total_alerts = len(alerts)

medium_alerts = int((alerts["severity"] == "MEDIUM").sum()) if not alerts.empty else 0
high_alerts = int((alerts["severity"] == "HIGH").sum()) if not alerts.empty else 0
critical_alerts = int((alerts["severity"] == "CRITICAL").sum()) if not alerts.empty else 0

port_scan_count = (
    int((alerts["detection"] == "TCP SYN scan").sum())
    if not alerts.empty else 0
)

syn_anomaly_count = (
    int((alerts["detection"] == "Repeated TCP SYN attempts").sum())
    if not alerts.empty else 0
)


# ==========================================================
# CSS
# ==========================================================

st.markdown(
    """
<style>
/* Remove the large Streamlit top gap */
[data-testid="stHeader"] {
    display: none;
}

[data-testid="stToolbar"] {
    display: none;
}

.block-container {
    padding-top: 1.2rem !important;
    padding-bottom: 2rem !important;
    max-width: 1500px !important;
}

/* App background */
.stApp {
    background: #f4f7fb;
}

/* Main title */
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #172554 100%);
    border-radius: 20px;
    padding: 25px 30px;
    margin-bottom: 18px;
    box-shadow: 0 10px 30px rgba(15, 23, 42, 0.14);
}

.hero-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
}

.hero-left {
    display: flex;
    align-items: center;
    gap: 15px;
}

.hero-icon {
    font-size: 42px;
}

.hero-title {
    color: white;
    font-size: 34px;
    font-weight: 800;
    line-height: 1.1;
    margin: 0;
}

.hero-subtitle {
    color: #cbd5e1;
    font-size: 14px;
    margin-top: 6px;
}

.live-badge {
    background: #064e3b;
    color: #6ee7b7;
    border: 1px solid #10b981;
    border-radius: 999px;
    padding: 9px 15px;
    font-size: 12px;
    font-weight: 800;
    white-space: nowrap;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 16px 18px;
    box-shadow: 0 5px 18px rgba(15, 23, 42, 0.06);
}

[data-testid="stMetricLabel"] {
    color: #64748b !important;
    font-weight: 700 !important;
}

[data-testid="stMetricValue"] {
    color: #0f172a !important;
    font-weight: 800 !important;
}

/* Section headings */
.section-title {
    color: #0f172a;
    font-size: 21px;
    font-weight: 800;
    margin: 20px 0 10px 0;
}

/* Latest alert */
.latest-alert {
    background: white;
    border-radius: 16px;
    padding: 18px 22px;
    border: 1px solid #e2e8f0;
    border-left: 6px solid #f59e0b;
    box-shadow: 0 5px 18px rgba(15, 23, 42, 0.06);
    margin-bottom: 12px;
}

.latest-label {
    color: #64748b;
    font-size: 11px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}

.latest-title {
    color: #0f172a;
    font-size: 19px;
    font-weight: 800;
    margin-top: 4px;
}

.latest-info {
    color: #64748b;
    font-size: 13px;
    margin-top: 7px;
}

/* Detection cards */
.detection-card {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 18px;
    box-shadow: 0 5px 18px rgba(15, 23, 42, 0.05);
}

.detection-label {
    color: #64748b;
    font-size: 12px;
    font-weight: 800;
    text-transform: uppercase;
}

.detection-value {
    color: #0f172a;
    font-size: 30px;
    font-weight: 800;
    margin-top: 5px;
}

/* Streamlit dataframe */
[data-testid="stDataFrame"] {
    border-radius: 14px;
    overflow: hidden;
    border: 1px solid #e2e8f0;
}

/* Chart containers */
.chart-box {
    background: white;
    border: 1px solid #e2e8f0;
    border-radius: 16px;
    padding: 14px 16px 6px 16px;
    box-shadow: 0 5px 18px rgba(15, 23, 42, 0.05);
}

/* Footer */
.footer {
    text-align: center;
    color: #94a3b8;
    font-size: 12px;
    padding-top: 20px;
    margin-top: 28px;
    border-top: 1px solid #e2e8f0;
}
</style>
""",
    unsafe_allow_html=True,
)


# ==========================================================
# HEADER
# ==========================================================

st.markdown(
    """
<div class="hero">
    <div class="hero-row">
        <div class="hero-left">
            <div class="hero-icon">🛡️</div>
            <div>
                <div class="hero-title">NetShield SOC</div>
                <div class="hero-subtitle">
                    Real-Time Network Security Monitoring & Threat Detection
                </div>
            </div>
        </div>
        <div class="live-badge">● MONITORING ACTIVE</div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)


# ==========================================================
# TOP METRICS
# ==========================================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("🚨 Total Alerts", total_alerts)

with col2:
    st.metric("🟡 Medium", medium_alerts)

with col3:
    st.metric("🟠 High", high_alerts)

with col4:
    st.metric("🔴 Critical", critical_alerts)


# ==========================================================
# LATEST ALERT
# ==========================================================

if not alerts.empty:
    latest = alerts.iloc[0]
    severity = str(latest["severity"])

    severity_color = {
        "CRITICAL": "#dc2626",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#22c55e",
    }.get(severity, "#2563eb")

    st.markdown(
        '<div class="section-title">⚡ Latest Security Alert</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
<div class="latest-alert" style="border-left-color:{severity_color};">
    <div class="latest-label">Latest Detection</div>
    <div class="latest-title">
        {latest["alert_type"]} &nbsp;•&nbsp; {severity}
    </div>
    <div class="latest-info">
        <b>{latest["source_ip"]}</b>
        &nbsp;→&nbsp;
        <b>{latest["destination_ip"]}</b>
        &nbsp;•&nbsp;
        {latest["detection"]}
        &nbsp;•&nbsp;
        {latest["timestamp"]}
    </div>
</div>
""",
        unsafe_allow_html=True,
    )
else:
    st.info("No security alerts have been detected yet.")


# ==========================================================
# DETECTION SUMMARY
# ==========================================================

st.markdown(
    '<div class="section-title">📊 Detection Summary</div>',
    unsafe_allow_html=True,
)

col1, col2 = st.columns(2)

with col1:
    st.markdown(
        f"""
<div class="detection-card">
    <div class="detection-label">TCP SYN Port Scans</div>
    <div class="detection-value">{port_scan_count}</div>
</div>
""",
        unsafe_allow_html=True,
    )

with col2:
    st.markdown(
        f"""
<div class="detection-card">
    <div class="detection-label">Repeated TCP SYN Anomalies</div>
    <div class="detection-value">{syn_anomaly_count}</div>
</div>
""",
        unsafe_allow_html=True,
    )


# ==========================================================
# SECURITY ALERT TABLE
# ==========================================================

st.markdown(
    '<div class="section-title">🚨 Security Alerts</div>',
    unsafe_allow_html=True,
)

if alerts.empty:
    st.info("No alerts available.")
else:
    display_alerts = alerts[
        [
            "timestamp",
            "alert_type",
            "severity",
            "source_ip",
            "destination_ip",
            "unique_ports",
            "detection",
        ]
    ].copy()

    display_alerts.columns = [
        "Timestamp",
        "Alert Type",
        "Severity",
        "Source IP",
        "Destination IP",
        "Count",
        "Detection",
    ]

    
    display_alerts = alerts[
    [
        "timestamp",
        "alert_type",
        "severity",
        "source_ip",
        "destination_ip",
        "unique_ports",
        "attempts",
        "detection",
    ]
].copy()
    
display_alerts["Count"] = display_alerts[
    ["unique_ports", "attempts"]
].bfill(axis=1).iloc[:, 0]

display_alerts = display_alerts[
    [
        "timestamp",
        "alert_type",
        "severity",
        "source_ip",
        "destination_ip",
        "Count",
        "detection",
    ]
]
st.dataframe(
        display_alerts,
        use_container_width=True,
        hide_index=True,
        height=360,
        column_config={
            "timestamp": st.column_config.TextColumn(
                "Timestamp",
                width="medium"
            ),
            "alert_type": st.column_config.TextColumn(
                "Alert Type",
                width="large"
            ),
            "severity": st.column_config.TextColumn(
                "Severity",
                width="small"
            ),
            "source_ip": st.column_config.TextColumn(
                "Source IP",
                width="medium"
            ),
            "destination_ip": st.column_config.TextColumn(
                "Destination IP",
                width="medium"
            ),
            "Count": st.column_config.NumberColumn(
                "Count",
                width="small"
            ),
            "detection": st.column_config.TextColumn(
                "Detection",
                width="large"
            ),
        }
    )


# ==========================================================
# ACTIVITY ANALYSIS
# ==========================================================

if not alerts.empty:

    st.markdown(
        '<div class="section-title">📈 Network Activity</div>',
        unsafe_allow_html=True,
    )

    chart_col1, chart_col2 = st.columns(2)


    # ======================================================
    # SOURCE IP CHART
    # ======================================================

    with chart_col1:

        source_counts = (
            alerts["source_ip"]
            .value_counts()
            .head(8)
            .reset_index()
        )

        source_counts.columns = [
            "Source IP",
            "Alerts"
        ]

        fig_source = px.bar(
            source_counts,
            x="Alerts",
            y="Source IP",
            orientation="h",
            text="Alerts",
        )

        fig_source.update_traces(
            textposition="outside",
            marker_color="#2563eb",
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Alerts: %{x}"
                "<extra></extra>"
            ),
        )

        fig_source.update_layout(
            title={
                "text": "Alerts by Source IP",
                "font": {
                    "size": 17,
                    "color": "#0f172a"
                },
            },

            xaxis={
                "title": "Number of Alerts",
                "dtick": 1,
                "showgrid": True,
                "gridcolor": "#e2e8f0",
                "zeroline": False,
            },

            yaxis={
                "title": "",
                "categoryorder": "total ascending",
            },

            plot_bgcolor="white",
            paper_bgcolor="white",

            height=330,

            margin=dict(
                l=20,
                r=50,
                t=60,
                b=45,
            ),

            font={
                "family": "Inter, Arial, sans-serif",
                "color": "#334155",
            },

            showlegend=False,
        )

        st.plotly_chart(
            fig_source,
            use_container_width=True,
            config={
                "displayModeBar": False
            },
        )


    # ======================================================
    # DETECTION TYPE CHART
    # ======================================================

    with chart_col2:

        detection_counts = (
            alerts["detection"]
            .value_counts()
            .reset_index()
        )

        detection_counts.columns = [
            "Detection",
            "Alerts"
        ]

        fig_detection = px.bar(
            detection_counts,
            x="Alerts",
            y="Detection",
            orientation="h",
            text="Alerts",
        )

        fig_detection.update_traces(
            textposition="outside",
            marker_color="#7c3aed",
            hovertemplate=(
                "<b>%{y}</b><br>"
                "Alerts: %{x}"
                "<extra></extra>"
            ),
        )

        fig_detection.update_layout(
            title={
                "text": "Alerts by Detection Type",
                "font": {
                    "size": 17,
                    "color": "#0f172a"
                },
            },

            xaxis={
                "title": "Number of Alerts",
                "dtick": 1,
                "showgrid": True,
                "gridcolor": "#e2e8f0",
                "zeroline": False,
            },

            yaxis={
                "title": "",
                "categoryorder": "total ascending",
            },

            plot_bgcolor="white",
            paper_bgcolor="white",

            height=330,

            margin=dict(
                l=20,
                r=50,
                t=60,
                b=45,
            ),

            font={
                "family": "Inter, Arial, sans-serif",
                "color": "#334155",
            },

            showlegend=False,
        )

        st.plotly_chart(
            fig_detection,
            use_container_width=True,
            config={
                "displayModeBar": False
            },
        )

# ==========================================================
# FOOTER
# ==========================================================

st.markdown(
    """
<div class="footer">
    NetShield SOC &nbsp;•&nbsp;
    TCP Network Monitoring &nbsp;•&nbsp;
    Threat Detection &nbsp;•&nbsp;
    Auto-refresh: 5 seconds
</div>
""",
    unsafe_allow_html=True,
)
