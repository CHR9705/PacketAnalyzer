import os
import sqlite3
from datetime import datetime
import time
import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(layout="wide", page_title="네트워크 공격 탐지 대시보드")

# TODO: 실제 DB 접속 정보에 맞게 수정하세요.
# SQLite가 아니라 PostgreSQL(psycopg2)을 쓰는 경우 load_warnings()의
# connect/query 부분만 바꿔주면 나머지 로직은 그대로 사용할 수 있습니다.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "packets.db"))

ATTACK_TYPES = [
    "ACK flood", "DNS Amplification", "Fin flood", "NULL Scan",
    "SSDP Amplification", "SYN flood", "SYN Scan", "FIN Scan",
    "RST flood", "UDP flood", "UDP Scan", "Xmas Scan",
]

GRADE_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "None": "🔵",
}

GRADE_COLORS = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#43a047",
    "None": "#1976d2",
}

# 차단 버튼을 눈에 띄는 빨간색으로 강조
st.markdown(
    """
    <style>
    button[kind="primary"] {
        background-color: #d32f2f !important;
        border-color: #d32f2f !important;
    }
    button[kind="primary"]:hover {
        background-color: #b71c1c !important;
        border-color: #b71c1c !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_warnings() -> pd.DataFrame:
    """warnings 테이블에서 경고 목록을 읽어온다."""
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query(
            """
            SELECT id, first_timestamp, last_timestamp, src_ip, attack_type, counter
            FROM warnings
            ORDER BY last_timestamp DESC
            """,
            conn,
        )
    finally:
        conn.close()
    return df


def grade_from_counter(counter: int) -> str:
    """발생 횟수(counter)를 기준으로 위험 등급을 계산한다.
    임계값은 팀 기준에 맞게 조정하세요."""
    if counter >= 200:
        return "Critical"
    elif counter >= 100:
        return "High"
    elif counter >= 50:
        return "Medium"
    elif counter >= 1:
        return "Low"
    return "None"


def grade_display(counter: int) -> str:
    """등급을 이모지와 함께 표시한다."""
    grade = grade_from_counter(counter)
    return f"{GRADE_EMOJI[grade]} {grade}"


def format_ts(value) -> str:
    """DB에 저장된 timestamp(유닉스 epoch 또는 문자열)를 사람이 읽기 쉬운 형태로 변환한다."""
    try:
        dt = pd.to_datetime(float(value), unit="s")
    except (ValueError, TypeError):
        dt = pd.to_datetime(value, errors="coerce")
    if pd.isna(dt):
        return str(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def field_html(label, value):
    """상세 카드에 들어갈 라벨-값 한 쌍의 HTML을 만든다."""
    label_style = "color:#666; font-size:0.85em; margin-bottom:2px;"
    value_style = "font-size:1.05em; font-weight:600;"
    return (
        "<div style='margin:0 0 10px 0;'>"
        f"<div style='{label_style}'>{label}</div>"
        f"<div style='{value_style}'>{value}</div>"
        "</div>"
    )


def add_to_blacklist(ip: str, accepted: bool = False):
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = 5000")
        existing = conn.execute("SELECT accepted FROM black_list WHERE ip = ? LIMIT 1", (ip,)).fetchone()
        if existing:
            if existing[0] == 2:
                return False, "차단해제로 등록된 IP입니다."
            return False, "이미 블랙리스트에 등록된 IP입니다."
        conn.execute(
            "INSERT INTO black_list (timestamp, ip, accepted) VALUES (?, ?, ?)",
            (time.time(), ip, 1 if accepted else 0),
        )
        return True, None
    except Exception as e:
        return False, str(e)

@st.dialog("차단 확인")
def confirm_block_dialog(row):
    ip = row['src_ip']

    st.write(f"Src IP {ip} 를 정말 차단하시겠습니까?")

    col1, col2 = st.columns(2, gap="small")
    with col1:
        if st.button("차단", key="confirm_block", type="primary", width="stretch"):
            success, err = add_to_blacklist(ip, accepted=True)
            if success:
                st.session_state.confirm_dialog_id = None
                st.session_state.block_error = None
                st.rerun()
            else:
                st.session_state.block_error = err  # 에러를 세션에 저장
                st.rerun()  # 다시 그려도 에러가 세션에 남아있으므로 표시됨
    with col2:
        if st.button("취소", key="cancel_block", width="stretch"):
            st.session_state.confirm_dialog_id = None
            st.session_state.block_error = None
            st.rerun()
    if st.session_state.get("block_error"):
        st.error(st.session_state.block_error)



st.title("경고 목록")

# --- 자동 새로고침 설정 ---
refresh_count = None
try:
    from streamlit_autorefresh import st_autorefresh
    refresh_count = st_autorefresh(interval=3000, key="data_refresh")
except ImportError:
    st.warning(
        "실시간 자동 새로고침을 사용하려면 터미널에서 "
        "`pip install streamlit-autorefresh` 를 실행하세요. "
        "(설치 전에는 페이지를 수동으로 새로고침해야 합니다.)"
    )

# --- 핵심 수정 포인트 ---
# 체크박스를 클릭하면 스크립트가 재실행되는데, 예전 코드는 재실행될 때마다
# 무조건 새 데이터를 추가해서 목록이 흔들리고 세부정보가 사라지는 문제가 있었다.
# st_autorefresh가 돌려주는 refresh_count가 "실제로 타이머가 울려서 재실행된 경우"에만
# 바뀌므로, 그때만 DB를 다시 읽어오고 체크박스 클릭으로 인한 재실행에서는
# 기존 데이터를 그대로 사용한다.
if "warnings_df" not in st.session_state:
    st.session_state.warnings_df = load_warnings()
    st.session_state.last_refresh_count = refresh_count
    st.session_state.last_updated = datetime.now()

if refresh_count is not None and refresh_count != st.session_state.last_refresh_count:
    st.session_state.warnings_df = load_warnings()
    st.session_state.last_refresh_count = refresh_count
    st.session_state.last_updated = datetime.now()

df = st.session_state.warnings_df


def on_table_edit():
    """packet_editor의 체크박스는 한 번에 하나만 선택되도록 한다.
    새 항목을 체크하면 이전 선택은 자동으로 해제된다."""
    edited_rows = st.session_state.get("packet_editor", {}).get("edited_rows", {})
    for row_idx, changes in edited_rows.items():
        if "선택" not in changes:
            continue
        row_id = st.session_state.display_ids[int(row_idx)]
        if changes["선택"]:
            st.session_state.selected_id = row_id
        elif st.session_state.get("selected_id") == row_id:
            st.session_state.selected_id = None


if "selected_id" not in st.session_state:
    st.session_state.selected_id = None

st.markdown(
    f"<div style='text-align:right; color:gray; font-size:0.85em;'>"
    f"마지막 업데이트: {st.session_state.last_updated.strftime('%Y-%m-%d %H:%M:%S')}</div>",
    unsafe_allow_html=True,
)

# --- 공격 유형별 카운트 차트 ---
counts = df["attack_type"].value_counts().reindex(ATTACK_TYPES, fill_value=0)
# 공격 유형별로 가장 심각한 등급(최대 counter 기준)을 구해서 막대 색상에 반영
max_counter_by_type = df.groupby("attack_type")["counter"].max().reindex(ATTACK_TYPES, fill_value=0)

chart_df = pd.DataFrame({
    "Attack Type": ATTACK_TYPES,
    "Attack Count": counts.values,
    "Grade": [grade_from_counter(c) for c in max_counter_by_type.values],
})

max_count = int(chart_df["Attack Count"].max()) if len(chart_df) else 0
y_domain_max = max_count if max_count > 0 else 1
y_ticks = list(range(0, max_count + 1))

base = alt.Chart(chart_df).encode(
    x=alt.X("Attack Type", sort=ATTACK_TYPES, title=None,
            axis=alt.Axis(labelAngle=-30)),
    y=alt.Y("Attack Count", title="Attack Count",
            scale=alt.Scale(domain=[0, y_domain_max], nice=False),
            axis=alt.Axis(values=y_ticks, format="d")),
)

bars = base.mark_bar(
    size=26, cornerRadiusTopLeft=4, cornerRadiusTopRight=4,
).encode(
    color=alt.Color(
        "Grade",
        scale=alt.Scale(domain=list(GRADE_COLORS.keys()), range=list(GRADE_COLORS.values())),
        legend=alt.Legend(title="Grade", orient="right"),
    ),
    tooltip=["Attack Type", "Attack Count", "Grade"],
)

labels = base.mark_text(align="center", baseline="bottom", dy=-4).encode(
    text=alt.Text("Attack Count:Q"),
)

chart = (bars + labels).properties(height=350)

st.altair_chart(chart, width="stretch")

st.divider()

col_list, col_detail = st.columns([1, 1])

with col_list:
    st.subheader("Attack Packet List")

    display_rows = df.head(50).to_dict("records")
    st.session_state.display_ids = [row["id"] for row in display_rows]

    table_df = pd.DataFrame({
        "선택": [row["id"] == st.session_state.selected_id for row in display_rows],
        "Timestamp": [format_ts(row["last_timestamp"]) for row in display_rows],
        "Attack Type": [row["attack_type"] for row in display_rows],
        "Src IP": [row["src_ip"] for row in display_rows],
        "Attack Grade": [grade_display(row["counter"]) for row in display_rows],
    })

    st.data_editor(
        table_df,
        column_config={
            "선택": st.column_config.CheckboxColumn("", width=20),
            "Timestamp": st.column_config.TextColumn("Timestamp", width="20"),
            "Attack Type": st.column_config.TextColumn("Attack Type", width="30"),
            "Src IP": st.column_config.TextColumn("Src IP", width="small"),
            "Attack Grade": st.column_config.TextColumn("Attack Grade", width="0.5"),
        },
        disabled=["Timestamp", "Attack Type", "Src IP", "Attack Grade"],
        hide_index=True,
        width="stretch",
        height=420,
        key="packet_editor",
        on_change=on_table_edit,
    )

    selected_ids = [st.session_state.selected_id] if st.session_state.selected_id in st.session_state.display_ids else []

with col_detail:
    st.subheader("Packet Detail Analysis")

    if not selected_ids:
        st.info("좌측 목록에서 항목을 체크하면 세부 데이터가 여기에 표시됩니다.")
    else:
        rows_by_id = {row["id"]: row for row in display_rows}
        selected_row = rows_by_id[selected_ids[0]]
        grade = grade_display(selected_row["counter"])

        st.markdown("**Detail Data View**")

        card_style = (
            "border:1px solid #ddd; border-radius:8px; padding:16px 20px; "
            "background-color:#fafafa;"
        )

        card_html = f"<div style='{card_style}'>"
        card_html += field_html("ID", selected_row["id"])
        card_html += field_html("Attack Type", selected_row["attack_type"])
        card_html += field_html("Grade", grade)
        card_html += field_html("Src IP", selected_row["src_ip"])
        card_html += field_html("First Timestamp", format_ts(selected_row["first_timestamp"]))
        card_html += field_html("Last Timestamp", format_ts(selected_row["last_timestamp"]))
        card_html += field_html("Counter", selected_row["counter"])
        card_html += "</div>"

        st.markdown(card_html, unsafe_allow_html=True)

        st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)

        # 차단은 되돌릴 수 없는 액션이므로, 버튼을 누르면 팝업으로 한 번 더 확인받는다.
        # 팝업 열림 여부를 session_state에 저장해두어야, 3초마다 도는 자동 새로고침으로
        # 스크립트가 다시 실행되어도 팝업이 닫히지 않고 계속 떠 있는다.
        if st.button("차단하기", key="block_button", type="primary"):
            st.session_state.confirm_dialog_id = selected_row["id"]

        if st.session_state.get("confirm_dialog_id") == selected_row["id"]:
            confirm_block_dialog(selected_row)

        if selected_row["id"] in st.session_state.get("blocked_ids", set()):
            st.caption(f"차단됨: {selected_row['src_ip']}")