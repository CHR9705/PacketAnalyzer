"""
==========================================================
Packet Analyzer
details.py

SOC(Security Operation Center) Dashboard

Environment
------------
- Streamlit
- streamlit-aggrid 1.2.1.post2
- SQLite

Author : ChatGPT
==========================================================
"""

###########################################################
# Import
###########################################################

import sqlite3
import pandas as pd
import streamlit as st

from st_aggrid import (
    AgGrid,
    GridOptionsBuilder,
    GridUpdateMode,
    DataReturnMode
)

from datetime import datetime
from streamlit_autorefresh import st_autorefresh

###########################################################
# Page Config
###########################################################

st.set_page_config(
    page_title="Packet Analyzer",
    layout="wide"
)

###########################################################
# Auto Refresh
###########################################################

# 1초마다 자동 새로고침
st_autorefresh(
    interval=1000,
    key="refresh"
)

###########################################################
# CSS
###########################################################

st.markdown("""

<style>

body{

    background:#F5F7FA;

}

.block-container{

    padding-top:1rem;
    padding-bottom:1rem;

}

.main-title{

    font-size:34px;

    font-weight:700;

    color:#202124;

    margin-bottom:20px;

}

.section-title{

    font-size:23px;

    font-weight:700;

    color:#404040;

}

.kpi-card{

    background:white;

    padding:20px;

    border-radius:12px;

    box-shadow:0 2px 8px rgba(0,0,0,0.08);

}

.metric-title{

    color:#888;

    font-size:14px;

}

.metric-value{

    font-size:30px;

    font-weight:bold;

}

</style>

""", unsafe_allow_html=True)

###########################################################
# DB
###########################################################

@st.cache_resource
def get_connection():

    conn = sqlite3.connect(
        "packets.db",
        check_same_thread=False
    )

    return conn


conn = get_connection()

###########################################################
# Query Function
###########################################################

@st.cache_data(ttl=1)
def load_packets():

    query = """
    SELECT *
    FROM packets
    ORDER BY id DESC
    """

    return pd.read_sql(query, conn)


@st.cache_data(ttl=1)
def load_warnings():

    query = """
    SELECT *
    FROM warnings
    ORDER BY last_timestamp DESC
    """

    return pd.read_sql(query, conn)


@st.cache_data(ttl=1)
def load_flows():

    query = """
    SELECT *
    FROM flows
    ORDER BY id DESC
    """

    return pd.read_sql(query, conn)

###########################################################
# Load
###########################################################

packet_df = load_packets()

warning_df = load_warnings()

flow_df = load_flows()

###########################################################
# Time Convert
###########################################################

def unix_to_time(ts):

    try:

        return datetime.fromtimestamp(
            ts
        ).strftime("%Y-%m-%d %H:%M:%S")

    except:

        return "-"

###########################################################
# Convert Timestamp
###########################################################

if len(packet_df):

    packet_df["timestamp"] = packet_df[
        "timestamp"
    ].apply(unix_to_time)

if len(warning_df):

    warning_df["first_timestamp"] = warning_df[
        "first_timestamp"
    ].apply(unix_to_time)

    warning_df["last_timestamp"] = warning_df[
        "last_timestamp"
    ].apply(unix_to_time)

if len(flow_df):

    flow_df["start_time"] = flow_df[
        "start_time"
    ].apply(unix_to_time)

    flow_df["last_seen"] = flow_df[
        "last_seen"
    ].apply(unix_to_time)

###########################################################
# Header
###########################################################

st.markdown(

'<div class="main-title">🛡 Packet Analyzer SOC Dashboard</div>',

unsafe_allow_html=True

)

###########################################################
# KPI
###########################################################

col1,col2,col3,col4=st.columns(4)

with col1:

    st.metric(

        "Packets",

        len(packet_df)

    )

with col2:

    st.metric(

        "Warnings",

        len(warning_df)

    )

with col3:

    st.metric(

        "Flows",

        len(flow_df)

    )

with col4:

    if len(packet_df):

        st.metric(

            "Protocols",

            packet_df["protocol"].nunique()

        )

    else:

        st.metric(

            "Protocols",

            0

        )

###########################################################
# Sidebar
###########################################################

st.sidebar.title("Search Filter")

search=st.sidebar.text_input(
    "Search"
)

protocol=st.sidebar.selectbox(

    "Protocol",

    ["ALL"]+

    sorted(

        packet_df["protocol"].dropna().unique().tolist()

    ) if len(packet_df)

    else ["ALL"]

)

flag=st.sidebar.selectbox(

    "TCP Flag",

    ["ALL"]+

    sorted(

        packet_df["tcp_flags"].fillna("").unique().tolist()

    ) if len(packet_df)

    else ["ALL"]

)

ip_filter=st.sidebar.text_input(

    "IP Address"

)

size_filter=st.sidebar.slider(

    "Packet Size",

    0,

    2000,

    (0,2000)

)