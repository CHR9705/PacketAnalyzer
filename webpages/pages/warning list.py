"""
네트워크 공격 탐지 대시보드 (Streamlit)

실행 방법:
    pip install streamlit pandas altair streamlit-autorefresh
    streamlit run attack_dashboard.py

구성:
  1) 상단: 공격 유형별 세로 막대그래프 (경고 목록)
  2) 하단 좌측: Attack Packet List
     - 컬럼 순서: 체크박스 / Timestamp / Attack Type / Src IP / Attack Grade
  3) 하단 우측: Packet Detail Analysis
     - 좌측 목록에서 체크한 패킷만 실시간으로 세부 데이터 표시
"""

import random
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(layout="wide", page_title="네트워크 공격 탐지 대시보드")

# ---------- 실시간 자동 새로고침 (선택 사항) ----------
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=3000, key="data_refresh")  # 3초마다 새 데이터 반영
except ImportError:
    st.warning(
        "실시간 자동 새로고침을 사용하려면 터미널에서 "
        "`pip install streamlit-autorefresh` 를 실행하세요. "
        "(설치 전에는 페이지를 수동으로 새로고침해야 합니다.)"
    )

ATTACK_TYPES = [
    "ACK flood", "DNS Amplification", "Fin flood", "NULL Scan",
    "SSDP Amplification", "SYN flood", "SYN Scan", "FIN Scan",
    "RST flood", "UDP flood", "UDP Scan", "Xmas Scan",
]
GRADES = ["High", "Medium", "Low"]


def random_ip() -> str:
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_packet() -> dict:
    """실제 서비스에서는 이 함수 대신 DB/큐/탐지 모듈로부터 실제 패킷 데이터를 받아오면 됩니다.
    화면에서 쓰이지 않는 필드(Dst IP, Protocol 등)는 만들지 않습니다.
    나중에 필요해지면 여기에 키만 추가하면 됩니다."""
    attack = random.choice(ATTACK_TYPES)
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Attack Type": attack,
        "Src IP": random_ip(),
        "Attack Grade": random.choice(GRADES),
        "Detail": (
            f"{attack} 패턴 감지 - 패킷 {random.randint(50, 500)}개, "
            f"PPS {random.randint(10, 100)}"
        ),
    }


# ---------- 세션 상태 초기화 ----------
if "packets" not in st.session_state:
    st.session_state.packets = [make_packet() for _ in range(15)]

# 새 패킷 유입 시뮬레이션 (실제 연동 시 이 블록을 실제 데이터 소스 폴링으로 교체)
if random.random() < 0.6:
    st.session_state.packets.insert(0, make_packet())
    st.session_state.packets = st.session_state.packets[:200]  # 최대 200개 유지

df = pd.DataFrame(st.session_state.packets)

st.title("경고 목록")

# ---------- 상단: 공격 유형별 세로 막대그래프 ----------
counts = df["Attack Type"].value_counts().reindex(ATTACK_TYPES, fill_value=0)
chart_df = counts.reset_index()
chart_df.columns = ["Attack Type", "Attack Count"]

chart = (
    alt.Chart(chart_df)
    .mark_bar(size=22)  # 막대 너비를 좁혀 가시성 개선 (숫자를 줄이면 더 얇아짐)
    .encode(
        x=alt.X("Attack Type", sort=ATTACK_TYPES, title=None,
                axis=alt.Axis(labelAngle=-30)),
        y=alt.Y("Attack Count", title="Attack Count"),
        tooltip=["Attack Type", "Attack Count"],
    )
    .properties(height=350)
)
st.altair_chart(chart, use_container_width=True)

st.divider()

col_list, col_detail = st.columns([1.3, 1])

# ---------- 하단 좌측: Attack Packet List ----------
with col_list:
    st.subheader("Attack Packet List")

    display_df = df[["Timestamp", "Attack Type", "Src IP", "Attack Grade"]].copy()
    display_df.insert(0, "선택", False)

    edited_df = st.data_editor(
        display_df,
        column_config={
            "선택": st.column_config.CheckboxColumn("", default=False),
            "Timestamp": st.column_config.TextColumn(disabled=True),
            "Attack Type": st.column_config.TextColumn(disabled=True),
            "Src IP": st.column_config.TextColumn(disabled=True),
            "Attack Grade": st.column_config.TextColumn(disabled=True),
        },
        hide_index=True,
        use_container_width=True,
        height=450,
        key="packet_editor",
    )

    selected_indices = edited_df[edited_df["선택"]].index.tolist()

# ---------- 하단 우측: Packet Detail Analysis ----------
with col_detail:
    st.subheader("Packet Detail Analysis")

    if not selected_indices:
        st.info("좌측 목록에서 항목을 체크하면 세부 데이터가 여기에 표시됩니다.")
    else:
        selected_df = df.loc[selected_indices]

        st.markdown("**Detail Data View**")
        detail_lines = [
            f"[{ts}] {detail}"
            for ts, detail in zip(selected_df["Timestamp"], selected_df["Detail"])
        ]
        st.text_area(
            "선택된 패킷 상세",
            "\n".join(detail_lines),
            height=150,
            disabled=True,
            label_visibility="collapsed",
        )

        st.markdown("**등급 (Grade Selection)**")
        st.selectbox(
            "Grade Selection", GRADES, key="grade_select",
            label_visibility="collapsed",
        )

        st.markdown("**차단**")
        st.toggle("차단 여부", key="block_toggle")

        st.markdown("**Analysis Notes**")
        st.text_area(
            "분석 메모", key="analysis_notes", height=120,
            label_visibility="collapsed",
        )

        st.caption(f"선택된 패킷 수: {len(selected_indices)}개")