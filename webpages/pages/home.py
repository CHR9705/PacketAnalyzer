import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timedelta

from streamlit_autorefresh import st_autorefresh

st_autorefresh(
    interval= 1 * 1000,   #1초마다 한번씩 새로고침
    key="home_refresh"
)

st.set_page_config(
    page_title="Packet Analyzer",
    layout="wide"
)

conn = sqlite3.connect("packets.db")
# conn = sqlite3.connect(r"C:\Users\RyunK_IT\Documents\vscodeProject\vm_shared\packets.db")

st.title("🛡 Packet Analyzer")

########################################################
# 최근 60초 데이터
########################################################

now = int(datetime.now().timestamp())
start = now - 60
one_day_ago = int((datetime.now() - timedelta(days=1)).timestamp())

packets = pd.read_sql_query("""
SELECT *
FROM packets
WHERE timestamp >= ?
""", conn, params=(start,))

warnings = pd.read_sql_query("""
SELECT *
FROM warnings
ORDER BY last_timestamp DESC
LIMIT 10
""", conn)

# flows = pd.read_sql_query("""
# SELECT *
# FROM flows
# WHERE last_seen >= ?
# """, conn, params=(one_day_ago, ))

########################################################
# KPI
########################################################

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total Packets",
        len(packets)
    )

with col2:
    st.metric(
        "PPS",
        round(len(packets)/60, 1)
    )

with col3:
    st.metric(
        "Warnings",
        len(warnings)
    )

with col4:
    st.metric(
        "Active Source IP",
        packets["src_ip"].nunique()
    )

# with col5:
#     max_flow = flows.loc[flows["packet_count"].idxmax()]
#     st.metric(
#         "24시간 내 최다 패킷 Flow",
#         f'{max_flow["endpoint1_ip"]} ↔\n {max_flow["endpoint2_ip"]}',
#         delta=f'{max_flow["packet_count"]} packets'
#     )

st.divider()


traffic = packets.copy()

traffic["second"] = traffic["timestamp"].astype(int)

traffic["time"] = pd.to_datetime(
    traffic["second"],
    unit="s"
)

traffic = (
    traffic
    .set_index("time")
    .resample("1s")
    .size()
    .reset_index(name="Packets")
)

fig = px.line(
    traffic,
    x="time",
    y="Packets",
    markers=True
)
st.plotly_chart(fig, width='stretch')

left, right = st.columns(2)
with left:

    st.subheader("Protocol Distribution")

    proto = (
        packets["protocol"]
        .value_counts()
        .reset_index()
    )

    proto.columns = ["Protocol", "Count"]

    fig = px.pie(
        proto,
        names="Protocol",
        values="Count"
    )

    st.plotly_chart(fig, width='stretch')

with right:

    st.subheader("Recent Alerts")

    if warnings.empty:
        st.success("No Warning")

    else:

        for _, row in warnings.iterrows():

            st.error(
                f"""
{row.attack_type}

IP : {row.src_ip}
Count : {row.counter}
"""
            )

left, right = st.columns(2)
with left:

    st.subheader("Top Source IP")

    top = (
        packets.groupby("src_ip")
        .size()
        .sort_values(ascending=False)
        .head(10)
    )

    st.dataframe(top)
with right:

    st.subheader("Recent Packets")

    recent = packets.sort_values(
        "timestamp",
        ascending=False
    ).head(10)

    st.dataframe(
        recent[
            [
                "timestamp",
                "src_ip",
                "dst_ip",
                "protocol",
                "packet_size"
            ]
        ],
        width='stretch'
    )