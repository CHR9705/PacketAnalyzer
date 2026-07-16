import sqlite3
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timezone, timedelta
import time

from streamlit_autorefresh import st_autorefresh

from webpages.functions.titles  import get_h2

kst = timezone(timedelta(hours=9))

from  webpages.css.st_header import _setting
from  webpages.css.st_metric import metric_cards
from  webpages.css.st_alertbox import alret_box_style

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

_setting()

st.markdown("""
<h1 style="
    font-size:28px;
    margin:0;
">
Home
</h1>
""", unsafe_allow_html=True)

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
LIMIT 5
""", conn)

warnings_cnt = pd.read_sql_query("""
SELECT count(*) as cnt
FROM warnings
""", conn)


def check_new_warning():

    latest_ts = warnings["last_timestamp"].iloc[0]  # 숫자 값 그대로 사용
    now_ts = time.time()  # 현재 시각도 숫자(epoch)로

    if "last_flashed_ts" not in st.session_state:
        st.session_state.last_flashed_ts = None

    is_new = (
        (now_ts - latest_ts) < 5
        and latest_ts != st.session_state.last_flashed_ts
    )

    if is_new:
        st.session_state.last_flashed_ts = latest_ts

        st.markdown("""
        <style>
        @keyframes flash-red-fade {
            0%   { opacity: 0.55; }
            100% { opacity: 0; }
        }
        .flash-overlay {
            position: fixed;
            top: 0; left: 0;
            width: 100vw; height: 100vh;
            background-color: red;
            pointer-events: none;
            z-index: 999999;
            animation: flash-red-fade 1s ease-out forwards;
        }
        </style>
        <div class="flash-overlay"></div>
        """, unsafe_allow_html=True)

########################################################
# KPI
########################################################

# components.iframe(
#     "http://localhost:3000/d/adnpnxq/new-dashboard?orgId=1&from=now-1m&to=now&timezone=browser&refresh=5s&kiosk",
#     height=600,
#     scrolling=True
# )


metric_cards()

# packet_size 합계 (바이트 단위라고 가정)
total_bytes = packets["packet_size"].sum()

# bps 계산 (비트 단위)
bps = (total_bytes * 8) / 60

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "분당 패킷 수",
        len(packets)
    )

with col2:
    st.metric(
        "PPS",
        round(len(packets)/60, 1)
    )

with col3:
    st.metric(
        "BPS",
        f"{bps/1000:.1f} Kbps"
    )

with col4:
    st.metric(
        "Warnings",
        warnings_cnt['cnt']
    )

with col5:
    st.metric(
        "활성 IP",
        packets["src_ip"].nunique()
    )

# st.divider()


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

fig.update_layout(
    height = 200,
    margin=dict(l=20, r=20, t=20, b=20),
)

st.plotly_chart(fig, width='stretch')

left, right = st.columns(2)
with left:

    st.markdown(get_h2("프로토콜 비율"), unsafe_allow_html=True)

    proto = (
        packets["protocol"]
        .value_counts()
        .reset_index()
    )

    proto.columns = ["Protocol", "Count"]


    fig = px.bar(
        proto,
        x="Count",
        y="Protocol",
        orientation="h",
        color="Protocol",
        text="Count"
    )

    fig.update_traces(textposition="outside")

    fig.update_layout(
        xaxis_title="Packets",
        yaxis_title=None,
        height=200,
        width=70,
        showlegend=False
    )

    left_margin, graph, right_margin = st.columns([0.3, 9, 0.7])

    with graph:
        st.plotly_chart(fig, width="stretch")

    # st.plotly_chart(fig, width="stretch")

  
alret_box_style()

with right:

    st.markdown(get_h2("최근 경고"), unsafe_allow_html=True)

    if warnings.empty:
        st.success("No Warning")

    else:

        for _, row in warnings.iterrows():
            last_time = datetime.fromtimestamp(row.last_timestamp, tz=kst).strftime("%Y-%m-%d %H:%M:%S")
            st.markdown(f"""
<div class="alert-div">
    <span>{row.attack_type}</span>
    <span>{row.src_ip}</span>
    <span>{last_time}</span>
    <span class="alert-cnt-span">{row.counter}</span>
</div>
""", unsafe_allow_html=True)


left, right = st.columns(2)
with left:

    st.markdown(get_h2("최다 IP"), unsafe_allow_html=True)

    top = (
    packets.groupby("src_ip")
    .size()
    .reset_index(name="Packets")
    .sort_values("Packets", ascending=False)
    .head(5)
    .rename(columns={"src_ip": "Source IP"})
)

    st.dataframe(
        top,
        hide_index=True,
        width='stretch',
        column_config={
            "Source IP": st.column_config.TextColumn(
                "Source IP",
                width="large"
            ),
            "Packets": st.column_config.NumberColumn(
                "횟수",
                width="small",
                format="%d"
            )
        }
    )
with right:
    st.markdown(get_h2("최근 패킷"), unsafe_allow_html=True)


    recent = (
        packets.sort_values("timestamp", ascending=False)
        .head(5)
        .copy()
    )

    recent["Time"] = (
    pd.to_datetime(recent["timestamp"], unit="s", utc=True)
      .dt.tz_convert("Asia/Seoul")
      .dt.strftime("%Y-%m-%d %H:%M:%S")
)

    # 표시할 컬럼 선택 및 이름 변경
    recent = recent.rename(columns={
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "protocol": "Protocol",
        "packet_size": "Size (B)"
    })

    st.dataframe(
        recent[
            [
                "Time",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Size (B)"
            ]
        ],
        hide_index=True,
        width="stretch",
        column_config={
            "Time": st.column_config.TextColumn(
                "Time",
                width="small"
            ),
            "Source IP": st.column_config.TextColumn(
                "Source IP",
                width="medium"
            ),
            "Destination IP": st.column_config.TextColumn(
                "Destination IP",
                width="medium"
            ),
            "Protocol": st.column_config.TextColumn(
                "Protocol",
                width="small"
            ),
            "Size (B)": st.column_config.NumberColumn(
                "Packet Size",
                width="small",
                format="%d B"
            ),
        }
    )

check_new_warning()
