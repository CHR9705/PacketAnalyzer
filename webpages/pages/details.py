# ============================================================
# Part 1-1
# Import / Config / Constants
# Packet Analyzer Dashboard
# ============================================================

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk

from st_aggrid import (
    AgGrid,
    GridOptionsBuilder,
    GridUpdateMode,
    DataReturnMode,
    JsCode
)

# ------------------------------------------------------------
# Streamlit Config
# ------------------------------------------------------------

st.set_page_config(
    page_title="Packet Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ------------------------------------------------------------
# Auto Refresh
# ------------------------------------------------------------

st_autorefresh(
    interval=1000,
    key="dashboard_refresh"
)

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DB_PATH = BASE_DIR / "packets.db"

# ------------------------------------------------------------
# Layout
# ------------------------------------------------------------

PAGE_WIDTH = 1920
PAGE_HEIGHT = 1080

HEADER_HEIGHT = 70
KPI_HEIGHT = 105
GRID_HEIGHT = 355
DETAIL_HEIGHT = 250
CHART_HEIGHT = 330

# ------------------------------------------------------------
# Grid
# ------------------------------------------------------------

GRID_THEME = "streamlit"

GRID_SELECTION = "single"

DEFAULT_PAGE_SIZE = 100

# ------------------------------------------------------------
# Database
# ------------------------------------------------------------

PACKET_TABLE = "packets"

FLOW_TABLE = "flows"

WARNING_TABLE = "warnings"

SQLITE_TIMEOUT = 10

# ------------------------------------------------------------
# Dashboard Colors
# ------------------------------------------------------------

PRIMARY = "#2563EB"
SUCCESS = "#16A34A"
WARNING = "#F59E0B"
DANGER = "#DC2626"

TEXT = "#111827"
SUBTEXT = "#6B7280"

CARD = "#FFFFFF"
BACKGROUND = "#F4F7FB"

BORDER = "#E5E7EB"

# ------------------------------------------------------------
# Protocol Color
# ------------------------------------------------------------

PROTOCOL_COLOR = {
    "TCP": "#2563EB",
    "UDP": "#10B981",
    "ICMP": "#F59E0B",
    "ARP": "#8B5CF6"
}

# ------------------------------------------------------------
# TCP Flag Color
# ------------------------------------------------------------

FLAG_COLOR = {
    "SYN": "#2563EB",
    "ACK": "#16A34A",
    "FIN": "#F97316",
    "RST": "#DC2626",
    "PSH": "#7C3AED",
    "URG": "#EC4899"
}

# ------------------------------------------------------------
# World Map Default
# ------------------------------------------------------------

DEFAULT_LAT = 20.0
DEFAULT_LON = 0.0
DEFAULT_ZOOM = 1.2
DEFAULT_PITCH = 0

# ------------------------------------------------------------
# AgGrid JS
# ------------------------------------------------------------

ROW_STYLE = JsCode(
    """
    function(params){
        return {
            'fontSize':'13px',
            'fontFamily':'Segoe UI',
            'borderBottom':'1px solid #ECECEC'
        }
    }
    """
)

CELL_CENTER = JsCode(
    """
    function(params){
        return {
            'display':'flex',
            'alignItems':'center'
        }
    }
    """
)

# ------------------------------------------------------------
# DataFrame Columns
# ------------------------------------------------------------

PACKET_COLUMNS = [
    "id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_size",
    "payload_size",
    "tcp_flags"
]

FLOW_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration",
    "pps"
]

WARNING_COLUMNS = [
    "id",
    "timestamp",
    "level",
    "attack_type",
    "src_ip",
    "dst_ip",
    "description"
]

# ------------------------------------------------------------
# Session State
# ------------------------------------------------------------

if "selected_packet" not in st.session_state:
    st.session_state.selected_packet = None

if "selected_flow" not in st.session_state:
    st.session_state.selected_flow = None

if "selected_warning" not in st.session_state:
    st.session_state.selected_warning = None

# ============================================================
# Part 1-2
# CSS (Microsoft Defender + Fluent UI Style)
# ============================================================

st.markdown(
    """
<style>

/* ==========================================================
   Global
========================================================== */

html, body, [class*="css"]{
    font-family: "Segoe UI","Malgun Gothic",sans-serif;
    background:#F4F7FB;
    color:#1F2937;
}

/* Streamlit */

.block-container{
    max-width:100%;
    padding-top:12px;
    padding-left:18px;
    padding-right:18px;
    padding-bottom:12px;
}

section.main>div{
    padding-top:0rem;
}

/* Hide Streamlit */

#MainMenu{
    visibility:hidden;
}

footer{
    visibility:hidden;
}

header{
    visibility:hidden;
}

/* ==========================================================
   Header
========================================================== */

.dashboard-header{

    background:white;

    border:1px solid #E5E7EB;

    border-radius:14px;

    padding:18px 26px;

    margin-bottom:14px;

    display:flex;

    justify-content:space-between;

    align-items:center;

    box-shadow:0 2px 8px rgba(0,0,0,.04);

}

.header-title{

    font-size:28px;

    font-weight:700;

    color:#1E3A8A;

}

.header-sub{

    font-size:13px;

    color:#6B7280;

    margin-top:4px;

}

.header-right{

    text-align:right;

}

.header-clock{

    font-size:22px;

    font-weight:700;

}

.header-date{

    font-size:13px;

    color:#6B7280;

}

/* ==========================================================
   KPI
========================================================== */

.kpi-card{

    background:white;

    border-radius:14px;

    border:1px solid #E5E7EB;

    padding:18px;

    transition:.2s;

    height:112px;

    box-shadow:0 1px 4px rgba(0,0,0,.04);

}

.kpi-card:hover{

    transform:translateY(-2px);

    box-shadow:0 6px 16px rgba(0,0,0,.08);

}

.kpi-title{

    font-size:13px;

    color:#6B7280;

    margin-bottom:10px;

    font-weight:600;

}

.kpi-value{

    font-size:31px;

    font-weight:700;

    color:#111827;

}

.kpi-footer{

    margin-top:8px;

    font-size:12px;

    color:#9CA3AF;

}

/* ==========================================================
   Toolbar
========================================================== */

.toolbar{

    background:white;

    border-radius:14px;

    border:1px solid #E5E7EB;

    padding:14px 18px;

    margin-top:14px;

    margin-bottom:14px;

    box-shadow:0 1px 4px rgba(0,0,0,.04);

}

/* ==========================================================
   Panel
========================================================== */

.panel{

    background:white;

    border-radius:14px;

    border:1px solid #E5E7EB;

    padding:14px;

    margin-bottom:14px;

    box-shadow:0 1px 4px rgba(0,0,0,.04);

}

.panel-title{

    font-size:18px;

    font-weight:700;

    color:#1F2937;

    margin-bottom:10px;

}

/* ==========================================================
   Detail
========================================================== */

.detail-box{

    background:#FAFBFC;

    border:1px solid #E5E7EB;

    border-radius:10px;

    padding:12px;

    min-height:180px;

}

.detail-title{

    font-size:17px;

    font-weight:700;

    margin-bottom:12px;

    color:#2563EB;

}

.detail-row{

    display:flex;

    justify-content:space-between;

    border-bottom:1px solid #F3F4F6;

    padding:7px 0;

    font-size:13px;

}

.detail-key{

    color:#6B7280;

    font-weight:600;

}

.detail-value{

    color:#111827;

    font-weight:500;

}

/* ==========================================================
   Chart
========================================================== */

.chart-card{

    background:white;

    border-radius:14px;

    border:1px solid #E5E7EB;

    padding:12px;

    box-shadow:0 1px 4px rgba(0,0,0,.04);

}

/* ==========================================================
   Status Badge
========================================================== */

.badge{

    display:inline-block;

    padding:3px 10px;

    border-radius:30px;

    font-size:12px;

    font-weight:600;

    color:white;

}

.badge-green{

    background:#16A34A;

}

.badge-red{

    background:#DC2626;

}

.badge-blue{

    background:#2563EB;

}

.badge-orange{

    background:#F59E0B;

}

.badge-purple{

    background:#7C3AED;

}

/* ==========================================================
   Footer
========================================================== */

.footer{

    margin-top:10px;

    padding:12px;

    text-align:center;

    color:#6B7280;

    font-size:12px;

}

/* ==========================================================
   AgGrid
========================================================== */

.ag-theme-streamlit{

    --ag-font-size:13px;

    --ag-font-family:Segoe UI;

    --ag-row-height:36px;

    --ag-header-height:38px;

    --ag-border-color:#E5E7EB;

    --ag-header-background-color:#F8FAFC;

    --ag-background-color:#FFFFFF;

    --ag-odd-row-background-color:#FCFCFD;

    --ag-row-hover-color:#EEF6FF;

    --ag-selected-row-background-color:#DBEAFE;

    --ag-header-foreground-color:#374151;

    --ag-foreground-color:#111827;

}

/* ==========================================================
   Scroll
========================================================== */

::-webkit-scrollbar{

    width:10px;

    height:10px;

}

::-webkit-scrollbar-thumb{

    background:#CBD5E1;

    border-radius:10px;

}

::-webkit-scrollbar-track{

    background:#F8FAFC;

}

</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# Part 1-3A
# SQLite(DB)
# ============================================================

@st.cache_resource(show_spinner=False)
def get_connection() -> sqlite3.Connection:
    """
    SQLite Connection
    """

    conn = sqlite3.connect(
        DB_PATH,
        check_same_thread=False,
        timeout=SQLITE_TIMEOUT
    )

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-100000;")
    conn.execute("PRAGMA foreign_keys=ON;")

    return conn


CONN = get_connection()


# ============================================================
# Query
# ============================================================

def query_dataframe(sql: str, params: tuple = ()) -> pd.DataFrame:
    """
    SQL → DataFrame
    """

    try:

        return pd.read_sql_query(
            sql,
            CONN,
            params=params
        )

    except Exception:

        return pd.DataFrame()


# ============================================================
# Packet
# ============================================================

@st.cache_data(ttl=1, show_spinner=False)
def load_packets(limit: int = 1000) -> pd.DataFrame:

    sql = f"""
        SELECT
            id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_size,
            payload_size,
            tcp_flags
        FROM {PACKET_TABLE}
        ORDER BY id DESC
        LIMIT ?
    """

    return query_dataframe(sql, (limit,))


# ============================================================
# Flow
# ============================================================

@st.cache_data(ttl=1, show_spinner=False)
def load_flows(limit: int = 1000) -> pd.DataFrame:

    sql = f"""
        SELECT
            flow_id,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            packet_count,
            byte_count,
            duration,
            pps
        FROM {FLOW_TABLE}
        ORDER BY flow_id DESC
        LIMIT ?
    """

    return query_dataframe(sql, (limit,))


# ============================================================
# Warning
# ============================================================

@st.cache_data(ttl=1, show_spinner=False)
def load_warnings(limit: int = 300) -> pd.DataFrame:

    sql = f"""
        SELECT
            id,
            timestamp,
            level,
            attack_type,
            src_ip,
            dst_ip,
            description
        FROM {WARNING_TABLE}
        ORDER BY id DESC
        LIMIT ?
    """

    return query_dataframe(sql, (limit,))


# ============================================================
# Summary
# ============================================================

@st.cache_data(ttl=1, show_spinner=False)
def load_summary() -> dict:

    summary = {
        "packet_count": 0,
        "flow_count": 0,
        "warning_count": 0,
        "tcp_count": 0,
        "udp_count": 0,
    }

    try:

        summary["packet_count"] = CONN.execute(
            f"SELECT COUNT(*) FROM {PACKET_TABLE}"
        ).fetchone()[0]

        summary["flow_count"] = CONN.execute(
            f"SELECT COUNT(*) FROM {FLOW_TABLE}"
        ).fetchone()[0]

        summary["warning_count"] = CONN.execute(
            f"SELECT COUNT(*) FROM {WARNING_TABLE}"
        ).fetchone()[0]

        summary["tcp_count"] = CONN.execute(
            f"SELECT COUNT(*) FROM {PACKET_TABLE} WHERE protocol='TCP'"
        ).fetchone()[0]

        summary["udp_count"] = CONN.execute(
            f"SELECT COUNT(*) FROM {PACKET_TABLE} WHERE protocol='UDP'"
        ).fetchone()[0]

    except Exception:
        pass

    return summary


# ============================================================
# Initial Load
# ============================================================

packet_df = load_packets()

flow_df = load_flows()

warning_df = load_warnings()

summary = load_summary()

# ============================================================
# Part 1-3B
# Utility Functions
# ============================================================

def safe_int(value, default=0):
    """
    None -> 0
    """

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    """
    None -> 0.0
    """

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_str(value, default="-"):
    """
    None -> "-"
    """

    if value is None:
        return default

    text = str(value).strip()

    return text if text else default


def format_timestamp(value):
    """
    Unix Timestamp -> YYYY-MM-DD HH:MM:SS
    """

    if value is None:
        return "-"

    try:

        value = float(value)

        if value > 1_000_000_000_000:
            value /= 1000

        return datetime.fromtimestamp(value).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:
        return str(value)


def format_number(value):
    """
    1000000 -> 1,000,000
    """

    try:
        return f"{int(value):,}"
    except Exception:
        return "0"


def format_bytes(size):

    try:
        size = float(size)
    except Exception:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]

    index = 0

    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1

    return f"{size:.2f} {units[index]}"


def protocol_badge(protocol):

    protocol = safe_str(protocol).upper()

    color = PROTOCOL_COLOR.get(protocol, "#6B7280")

    return (
        f"<span class='badge' "
        f"style='background:{color};'>"
        f"{protocol}"
        f"</span>"
    )


def flag_badge(flag):

    if not flag:
        return "-"

    html = []

    for item in str(flag).replace(",", " ").split():

        key = item.upper()

        color = FLAG_COLOR.get(key, "#6B7280")

        html.append(
            f"<span class='badge' "
            f"style='background:{color};margin-right:4px;'>"
            f"{key}"
            f"</span>"
        )

    return "".join(html)


def make_detail_dataframe(data: dict) -> pd.DataFrame:

    rows = []

    for key, value in data.items():

        rows.append(
            {
                "Field": key,
                "Value": safe_str(value)
            }
        )

    return pd.DataFrame(rows)


def get_protocol_count(df: pd.DataFrame, protocol: str) -> int:

    if df.empty:
        return 0

    if "protocol" not in df.columns:
        return 0

    return int(
        (df["protocol"] == protocol).sum()
    )


def get_unique_ip_count(df: pd.DataFrame) -> int:

    if df.empty:
        return 0

    ips = set()

    if "src_ip" in df.columns:
        ips.update(df["src_ip"].dropna().tolist())

    if "dst_ip" in df.columns:
        ips.update(df["dst_ip"].dropna().tolist())

    return len(ips)


def get_latest_timestamp(df: pd.DataFrame):

    if df.empty:
        return "-"

    if "timestamp" not in df.columns:
        return "-"

    return format_timestamp(df.iloc[0]["timestamp"])


def dataframe_to_csv(df: pd.DataFrame):

    if df.empty:
        return b""

    return df.to_csv(
        index=False,
        encoding="utf-8-sig"
    ).encode("utf-8-sig")


def empty_dataframe(columns):

    return pd.DataFrame(columns=columns)


def refresh_data():

    return {
        "packet": load_packets(),
        "flow": load_flows(),
        "warning": load_warnings(),
        "summary": load_summary()
    }


# ============================================================
# Refresh
# ============================================================

data = refresh_data()

packet_df = data["packet"]

flow_df = data["flow"]

warning_df = data["warning"]

summary = data["summary"]

# ============================================================
# Part 1-4
# Header, KPI
# ============================================================

# ------------------------------------------------------------
# Current Time
# ------------------------------------------------------------

current_time = datetime.now()

current_date = current_time.strftime("%Y-%m-%d")

current_clock = current_time.strftime("%H:%M:%S")

# ------------------------------------------------------------
# KPI Value
# ------------------------------------------------------------

total_packets = safe_int(summary.get("packet_count"))

total_flows = safe_int(summary.get("flow_count"))

total_warnings = safe_int(summary.get("warning_count"))

tcp_packets = safe_int(summary.get("tcp_count"))

udp_packets = safe_int(summary.get("udp_count"))

unique_ips = get_unique_ip_count(packet_df)

latest_packet = get_latest_timestamp(packet_df)

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

header_left, header_right = st.columns([5, 1])

with header_left:
    st.title("🛡️ Packet Analyzer Dashboard")
    st.caption("Real-Time Network Traffic Monitoring")

with header_right:
    st.markdown("### " + current_clock)
    st.caption(current_date)

st.markdown("---")

# ------------------------------------------------------------
# KPI
# ------------------------------------------------------------

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

with kpi1:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
Total Packets
</div>

<div class="kpi-value">
{format_number(total_packets)}
</div>

<div class="kpi-footer">
Captured Packets
</div>

</div>
""",
        unsafe_allow_html=True
    )

with kpi2:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
Active Flows
</div>

<div class="kpi-value">
{format_number(total_flows)}
</div>

<div class="kpi-footer">
Network Flows
</div>

</div>
""",
        unsafe_allow_html=True
    )

with kpi3:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
Warnings
</div>

<div class="kpi-value" style="color:#DC2626;">
{format_number(total_warnings)}
</div>

<div class="kpi-footer">
Detected Events
</div>

</div>
""",
        unsafe_allow_html=True
    )

with kpi4:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
TCP Packets
</div>

<div class="kpi-value" style="color:#2563EB;">
{format_number(tcp_packets)}
</div>

<div class="kpi-footer">
Protocol : TCP
</div>

</div>
""",
        unsafe_allow_html=True
    )

with kpi5:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
UDP Packets
</div>

<div class="kpi-value" style="color:#16A34A;">
{format_number(udp_packets)}
</div>

<div class="kpi-footer">
Protocol : UDP
</div>

</div>
""",
        unsafe_allow_html=True
    )

with kpi6:

    st.markdown(
        f"""
<div class="kpi-card">

<div class="kpi-title">
Unique IP
</div>

<div class="kpi-value">
{format_number(unique_ips)}
</div>

<div class="kpi-footer">
Last Packet : {latest_packet}
</div>

</div>
""",
        unsafe_allow_html=True
    )

st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)

# ============================================================
# Part 2-1
# Search Toolbar
# ============================================================

st.markdown(
    """
<div class="panel">

<div class="panel-title">
🔎 Search & Filter
</div>

</div>
""",
    unsafe_allow_html=True
)

toolbar_col1, toolbar_col2, toolbar_col3, toolbar_col4, toolbar_col5, toolbar_col6 = st.columns(
    [2.5, 1.1, 1.1, 1.0, 1.0, 0.8]
)

with toolbar_col1:

    search_keyword = st.text_input(
        "Search",
        placeholder="IP / Port / Protocol / TCP Flag ...",
        label_visibility="collapsed"
    )

with toolbar_col2:

    protocol_filter = st.selectbox(
        "Protocol",
        [
            "ALL",
            "TCP",
            "UDP",
            "ICMP",
            "ARP"
        ]
    )

with toolbar_col3:

    flag_filter = st.selectbox(
        "TCP Flag",
        [
            "ALL",
            "SYN",
            "ACK",
            "FIN",
            "RST",
            "PSH",
            "URG"
        ]
    )

with toolbar_col4:

    min_packet_size = st.number_input(
        "Min Size",
        min_value=0,
        value=0,
        step=1
    )

with toolbar_col5:

    max_packet_size = st.number_input(
        "Max Size",
        min_value=0,
        value=65535,
        step=100
    )

with toolbar_col6:

    st.markdown(
        "<div style='height:27px;'></div>",
        unsafe_allow_html=True
    )

    csv_packet = dataframe_to_csv(packet_df)

    st.download_button(
        "📥 CSV",
        data=csv_packet,
        file_name="packets.csv",
        mime="text/csv",
        use_container_width=True
    )

st.markdown("<br>", unsafe_allow_html=True)

# ============================================================
# Part 2-2
# SQLite Query + Filter
# ============================================================

def apply_packet_filter(
    packet_df: pd.DataFrame,
    keyword: str,
    protocol: str,
    tcp_flag: str,
    min_size: int,
    max_size: int,
) -> pd.DataFrame:
    """
    Packet DataFrame Filter
    """

    if packet_df.empty:
        return packet_df.copy()

    df = packet_df.copy()

    # --------------------------------------------------------
    # Packet Size
    # --------------------------------------------------------

    if "packet_size" in df.columns:

        df = df[
            (df["packet_size"] >= min_size)
            &
            (df["packet_size"] <= max_size)
        ]

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    if (
        protocol != "ALL"
        and "protocol" in df.columns
    ):

        df = df[
            df["protocol"].astype(str).str.upper() == protocol
        ]

    # --------------------------------------------------------
    # TCP Flag
    # --------------------------------------------------------

    if (
        tcp_flag != "ALL"
        and "tcp_flags" in df.columns
    ):

        df = df[
            df["tcp_flags"]
            .fillna("")
            .astype(str)
            .str.upper()
            .str.contains(
                tcp_flag,
                case=False,
                regex=False
            )
        ]

    # --------------------------------------------------------
    # Keyword Search
    # --------------------------------------------------------

    keyword = keyword.strip()

    if keyword:

        keyword = keyword.lower()

        search_columns = [
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "tcp_flags"
        ]

        mask = pd.Series(
            False,
            index=df.index
        )

        for column in search_columns:

            if column not in df.columns:
                continue

            mask |= (
                df[column]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(
                    keyword,
                    regex=False
                )
            )

        df = df[mask]

    # --------------------------------------------------------
    # Timestamp Format
    # --------------------------------------------------------

    if "timestamp" in df.columns:

        df["timestamp"] = (
            df["timestamp"]
            .apply(format_timestamp)
        )

    # --------------------------------------------------------
    # Sort
    # --------------------------------------------------------

    if "id" in df.columns:

        df = df.sort_values(
            by="id",
            ascending=False
        )

    return df.reset_index(drop=True)


# ============================================================
# Flow Filter
# ============================================================

def apply_flow_filter(
    flow_df: pd.DataFrame,
    keyword: str,
    protocol: str,
) -> pd.DataFrame:

    if flow_df.empty:
        return flow_df.copy()

    df = flow_df.copy()

    # --------------------------------------------------------
    # Protocol
    # --------------------------------------------------------

    if (
        protocol != "ALL"
        and "protocol" in df.columns
    ):

        df = df[
            df["protocol"]
            .astype(str)
            .str.upper()
            == protocol
        ]

    # --------------------------------------------------------
    # Keyword
    # --------------------------------------------------------

    keyword = keyword.strip()

    if keyword:

        keyword = keyword.lower()

        mask = pd.Series(
            False,
            index=df.index
        )

        columns = [
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol"
        ]

        for column in columns:

            if column not in df.columns:
                continue

            mask |= (
                df[column]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(
                    keyword,
                    regex=False
                )
            )

        df = df[mask]

    if "flow_id" in df.columns:

        df = df.sort_values(
            by="flow_id",
            ascending=False
        )

    return df.reset_index(drop=True)


# ============================================================
# Apply Filter
# ============================================================

packet_view = apply_packet_filter(
    packet_df=packet_df,
    keyword=search_keyword,
    protocol=protocol_filter,
    tcp_flag=flag_filter,
    min_size=min_packet_size,
    max_size=max_packet_size,
)

flow_view = apply_flow_filter(
    flow_df=flow_df,
    keyword=search_keyword,
    protocol=protocol_filter,
)

warning_view = warning_df.copy()

# ============================================================
# Result Count
# ============================================================

st.caption(
    f"""
Packets : {len(packet_view):,} |
Flows : {len(flow_view):,} |
Warnings : {len(warning_view):,}
"""
)

# ============================================================
# Part 3-1
# Packet Grid (AgGrid)
# ============================================================

monitor_col, detail_col = st.columns(
    [2.3, 1],
    gap="medium"
)

with monitor_col:

    st.markdown("### 📡 Traffic Monitor")

    monitor_type = st.radio(
        "",
        ["📦 Packet", "🔄 Flow"],
        horizontal=True,
        label_visibility="collapsed",
    )

    if monitor_type == "📦 Packet":

        current_df = packet_view

    else:

        current_df = flow_view

    packet_gb = GridOptionsBuilder.from_dataframe(
    current_df)

    packet_gb.configure_default_column(
        sortable=True,
        filter=True,
        resizable=True,
        editable=False,
        floatingFilter=False,
    )

    packet_gb.configure_selection(
        selection_mode="single",
        use_checkbox=False,
        pre_selected_rows=[],
    )

    packet_gb.configure_grid_options(
        rowHeight=34,
        headerHeight=38,
        animateRows=True,
        suppressRowClickSelection=False,
        rowSelection="single",
        enableCellTextSelection=True,
        ensureDomOrder=True,
    )
    
    packet_gb.configure_column(
        "id",
        header_name="ID",
        width=70,
        type=["numericColumn"],
    )

    packet_gb.configure_column(
        "timestamp",
        header_name="Timestamp",
        width=180,
    )

    packet_gb.configure_column(
        "src_ip",
        header_name="Source IP",
        width=150,
    )

    packet_gb.configure_column(
        "dst_ip",
        header_name="Destination IP",
        width=150,
    )

    packet_gb.configure_column(
        "src_port",
        header_name="Src Port",
        width=95,
        type=["numericColumn"],
    )

    packet_gb.configure_column(
        "dst_port",
        header_name="Dst Port",
        width=95,
        type=["numericColumn"],
    )

    packet_gb.configure_column(
        "protocol",
        header_name="Protocol",
        width=90,
    )

    packet_gb.configure_column(
        "packet_size",
        header_name="Size",
        width=90,
        type=["numericColumn"],
    )

    packet_gb.configure_column(
        "payload_size",
        header_name="Payload",
        width=95,
        type=["numericColumn"],
    )

    packet_gb.configure_column(
        "tcp_flags",
        header_name="TCP Flags",
        width=110,
    )

    packet_grid = AgGrid(
        current_df,
        key="packet_grid",
        gridOptions=packet_gb.build(),
        theme=GRID_THEME,
        allow_unsafe_jscode=True,
        height=GRID_HEIGHT,
        fit_columns_on_grid_load=False,
        data_return_mode=DataReturnMode.AS_INPUT,
        update_mode=GridUpdateMode.SELECTION_CHANGED,
        reload_data=True,
    )

    selected = None

    if packet_grid["selected_rows"]:

        selected = packet_grid["selected_rows"][0]

        st.session_state.selected_row = selected

    elif "selected_row" in st.session_state:

        selected = st.session_state.selected_row


# ============================================================
# Part 5
# Unified Detail Panel
# ============================================================

with detail_col:

    st.markdown("### 🔍 Detail")

st.markdown("<br>", unsafe_allow_html=True)

st.markdown(
    """
<div class="panel">

<div class="panel-title">
📋 Unified Detail Panel
</div>

</div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# Packet / Flow Detail
# ============================================================

with detail_col:

    st.markdown("### 🔍 Detail")

    if selected is None:

        st.info("Packet 또는 Flow를 선택하세요.")

    else:

        packet_detail = {

            "Packet ID": selected.get("id"),
            "Timestamp": selected.get("timestamp"),
            "Source IP": selected.get("src_ip"),
            "Destination IP": selected.get("dst_ip"),
            "Source Port": selected.get("src_port"),
            "Destination Port": selected.get("dst_port"),
            "Protocol": selected.get("protocol"),
            "Packet Size": selected.get("packet_size"),
            "Payload Size": selected.get("payload_size"),
            "TCP Flags": selected.get("tcp_flags"),

        }

        st.dataframe(
            make_detail_dataframe(packet_detail),
            use_container_width=True,
            hide_index=True,
            height=DETAIL_HEIGHT,
        )

# ============================================================
# Part 6-1
# Traffic Charts
# ============================================================

st.markdown("<br>", unsafe_allow_html=True)

chart_col1, chart_col2 = st.columns([1.3, 1.0], gap="medium")

# ============================================================
# Traffic Timeline
# ============================================================

with chart_col1:

    st.markdown(
        """
<div class="panel">
<div class="panel-title">
📈 Traffic Timeline
</div>
</div>
""",
        unsafe_allow_html=True,
    )

    if not packet_df.empty and "timestamp" in packet_df.columns:

        chart_df = packet_df.copy()

        try:

            chart_df["timestamp"] = pd.to_datetime(
                chart_df["timestamp"],
                unit="s",
                errors="coerce"
            )

        except Exception:

            chart_df["timestamp"] = pd.to_datetime(
                chart_df["timestamp"],
                errors="coerce"
            )

        chart_df = chart_df.dropna(subset=["timestamp"])

        if not chart_df.empty:

            chart_df["time"] = (
                chart_df["timestamp"]
                .dt.floor("1s")
            )

            traffic = (
                chart_df
                .groupby("time")
                .size()
                .reset_index(name="Packets")
            )

            fig = px.line(
                traffic,
                x="time",
                y="Packets",
                markers=True
            )

            fig.update_layout(
                margin=dict(l=10, r=10, t=10, b=10),
                height=CHART_HEIGHT,
                template="plotly_white",
                xaxis_title="Time",
                yaxis_title="Packets",
                hovermode="x unified"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

        else:

            st.info("No traffic data.")

    else:

        st.info("No traffic data.")

# ============================================================
# Protocol Distribution
# ============================================================

with chart_col2:

    st.markdown(
        """
<div class="panel">
<div class="panel-title">
📊 Protocol Distribution
</div>
</div>
""",
        unsafe_allow_html=True,
    )

    if (
        not packet_df.empty
        and "protocol" in packet_df.columns
    ):

        protocol_df = (
            packet_df["protocol"]
            .value_counts()
            .reset_index()
        )

        protocol_df.columns = [
            "Protocol",
            "Count"
        ]

        fig = px.pie(
            protocol_df,
            names="Protocol",
            values="Count",
            hole=0.45
        )

        fig.update_layout(
            template="plotly_white",
            margin=dict(l=10, r=10, t=10, b=10),
            height=CHART_HEIGHT,
            showlegend=True
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.info("No protocol data.")

# ============================================================
# Part 6-2
# World Map (PyDeck)
# ============================================================

st.markdown("<br>", unsafe_allow_html=True)

map_col, country_col = st.columns([1.45, 1.0], gap="medium")

# ============================================================
# World Map
# ============================================================

with map_col:

    st.markdown(
        """
<div class="panel">
<div class="panel-title">
🌍 World Traffic Map
</div>
</div>
""",
        unsafe_allow_html=True,
    )

    map_df = pd.DataFrame()

    if not packet_df.empty:

        if {"latitude", "longitude"}.issubset(packet_df.columns):

            map_df = (
                packet_df[
                    ["latitude", "longitude"]
                ]
                .dropna()
                .copy()
            )

            map_df.rename(
                columns={
                    "latitude": "lat",
                    "longitude": "lon"
                },
                inplace=True
            )

    if not map_df.empty:

        layer = pdk.Layer(
            "ScatterplotLayer",
            data=map_df,
            get_position="[lon, lat]",
            get_radius=20000,
            radius_min_pixels=3,
            radius_max_pixels=10,
            pickable=True,
            opacity=0.7,
        )

        view_state = pdk.ViewState(
            latitude=float(map_df["lat"].mean()),
            longitude=float(map_df["lon"].mean()),
            zoom=1.5,
            pitch=0,
        )

        deck = pdk.Deck(
            layers=[layer],
            initial_view_state=view_state,
            map_style="light",
            tooltip={
                "text": "Lat : {lat}\nLon : {lon}"
            },
        )

        st.pydeck_chart(deck, use_container_width=True)

    else:

        deck = pdk.Deck(
            initial_view_state=pdk.ViewState(
                latitude=DEFAULT_LAT,
                longitude=DEFAULT_LON,
                zoom=DEFAULT_ZOOM,
                pitch=DEFAULT_PITCH,
            ),
            map_style="light",
        )

        st.pydeck_chart(deck, use_container_width=True)

# ============================================================
# Country Distribution
# ============================================================

with country_col:

    st.markdown(
        """
<div class="panel">
<div class="panel-title">
🌎 Country Distribution
</div>
</div>
""",
        unsafe_allow_html=True,
    )

    if (
        not packet_df.empty
        and "country" in packet_df.columns
    ):

        country_df = (
            packet_df["country"]
            .fillna("Unknown")
            .value_counts()
            .reset_index()
        )

        country_df.columns = [
            "Country",
            "Count"
        ]

        fig = px.pie(
            country_df,
            names="Country",
            values="Count",
            hole=0.5,
        )

        fig.update_layout(
            template="plotly_white",
            margin=dict(l=10, r=10, t=10, b=10),
            height=CHART_HEIGHT,
            showlegend=True,
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info("Country information is not available.")

# ============================================================
# Part 7
# Footer
# ============================================================

st.markdown("<br>", unsafe_allow_html=True)

st.markdown(
    f"""
<div class="footer">

Packet Analyzer Dashboard |
Auto Refresh : 1 sec |
Packets : {format_number(total_packets)} |
Flows : {format_number(total_flows)} |
Warnings : {format_number(total_warnings)}

</div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# Part 8
# Finish / Runtime Validation
# ============================================================

# ------------------------------------------------------------
# Data Validation
# ------------------------------------------------------------

if packet_df is None:
    packet_df = empty_dataframe(PACKET_COLUMNS)

if flow_df is None:
    flow_df = empty_dataframe(FLOW_COLUMNS)

if warning_df is None:
    warning_df = empty_dataframe(WARNING_COLUMNS)

# ------------------------------------------------------------
# Type Convert
# ------------------------------------------------------------

for df in (packet_df, flow_df, warning_df):

    if df.empty:
        continue

    df.fillna("", inplace=True)

# ------------------------------------------------------------
# Sidebar Hide
# ------------------------------------------------------------

st.markdown(
    """
<script>

const sidebar = window.parent.document.querySelector('[data-testid="stSidebar"]');

if(sidebar){
    sidebar.style.display="none";
}

</script>
""",
    unsafe_allow_html=True
)

# ============================================================
# End
# ============================================================