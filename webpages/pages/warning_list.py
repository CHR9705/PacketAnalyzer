import os
import sqlite3
import time
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

st.set_page_config(layout="wide", page_title="네트워크 공격 탐지 대시보드")

from webpages.css.st_header import _setting
from webpages.css.st_glass import liquid_glass

_setting()
liquid_glass()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "packets.db"))

BLACKLIST_TABLE = "black_list"
WHITELIST_TABLE = "white_list"
IP_COLUMN = "ip"

GRADE_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "None": "🔵",
}

# 등급별 진한 색(차트, 뱃지 텍스트/테두리용)
GRADE_COLORS = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#43a047",
    "None": "#1976d2",
}

# 등급별 연한 배경색(뱃지 배경용) - 다크 카드 위에서 잘 보이도록 반투명 처리
GRADE_BG = {
    "Critical": "rgba(211, 47, 47, 0.18)",
    "High": "rgba(245, 124, 0, 0.18)",
    "Medium": "rgba(251, 192, 45, 0.18)",
    "Low": "rgba(67, 160, 71, 0.18)",
    "None": "rgba(25, 118, 210, 0.18)",
}

# --- 디자인 토큰 + 전역 스타일 ---
# 배경/카드/여백/폰트 위계를 하나의 스타일 시트로 통일해서 관리한다.
st.markdown(
    """
    <style>
    :root {
        --color-bg: #0e1117;
        --color-card-bg: rgba(255, 255, 255, 0.06);
        --color-border: rgba(255, 255, 255, 0.14);
        --color-text-primary: #e6e6e6;
        --color-text-secondary: #9aa0a6;
        --radius-md: 8px;
        --radius-lg: 20px;
        --shadow-sm: 0 8px 32px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.18);
        --space-2: 8px;
        --space-3: 16px;
        --space-4: 24px;
    }
    .stApp {
        color: var(--color-text-primary);
    }
    h1 {
        font-weight: 800 !important;
        color: var(--color-text-primary) !important;
    }
    h3 {
        font-weight: 600 !important;
        color: #b5bac1 !important;
        font-size: 1.15rem !important;
    }
    /* 차단 버튼을 눈에 띄는 빨간색으로 강조 */
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
    """표(data_editor)용: 등급을 이모지와 함께 텍스트로 표시한다."""
    grade = grade_from_counter(counter)
    return f"{GRADE_EMOJI[grade]} {grade}"


def grade_badge_html(grade: str) -> str:
    """상세 카드용: 등급을 색이 있는 뱃지(pill)로 표시한다."""
    color = GRADE_COLORS[grade]
    bg = GRADE_BG[grade]
    emoji = GRADE_EMOJI[grade]
    return (
        f"<span style='display:inline-block; padding:3px 12px; border-radius:999px; "
        f"background-color:{bg}; color:{color}; font-weight:700; font-size:0.9em;'>"
        f"{emoji} {grade}</span>"
    )


def format_ts(value) -> str:
    """DB에 저장된 유닉스 timestamp를 한국 시간(KST) 기준으로 사람이 읽기 쉬운 형태로 변환한다."""
    try:
        dt = pd.to_datetime(float(value), unit="s", utc=True)
        dt_kst = dt.tz_convert("Asia/Seoul")
        return dt_kst.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return str(value)


def field_grid_html(pairs, grade_color) -> str:
    """상세 카드 전체를 2열 그리드 HTML로 만든다.
    등급 색으로 카드 왼쪽에 컬러 바(border-left)를 주어 위험도를 한눈에 보이게 한다."""
    cells = "".join(
        "<div>"
        f"<div style='color:var(--color-text-secondary); font-size:0.82em; margin-bottom:2px;'>{label}</div>"
        f"<div style='font-size:1.02em; font-weight:600; color:var(--color-text-primary);'>{value}</div>"
        "</div>"
        for label, value in pairs
    )
    return (
        "<div style='border:1px solid var(--color-border); border-left:4px solid "
        f"{grade_color}; border-radius:var(--radius-lg); padding:20px var(--space-4); "
        "background-color:var(--color-card-bg); box-shadow:var(--shadow-sm); "
        "backdrop-filter:blur(24px) saturate(160%); "
        "-webkit-backdrop-filter:blur(24px) saturate(160%); "
        "display:grid; grid-template-columns:1fr 1fr; "
        f"gap:var(--space-3) var(--space-4);'>{cells}</div>"
    )


def add_to_blacklist(ip: str, accepted: bool = False):
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
        conn.execute("PRAGMA busy_timeout = 5000")
        existing = conn.execute(
            "SELECT accepted FROM black_list WHERE ip = ? LIMIT 1", (ip,)
        ).fetchone()
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


# 취소가 아닌 x 시 재팝업 방지 파라미터 적용
def reset_confirm_dialog():
    st.session_state.confirm_dialog_id = None
    st.session_state.block_error = None


@st.dialog("차단 확인", on_dismiss=reset_confirm_dialog)
def confirm_block_dialog(row):
    ip = row["src_ip"]
    st.write(f"Src IP **{ip}** 를 정말 차단하시겠습니까?")
    col1, col2 = st.columns(2, gap="small")
    with col1:
        if st.button("차단", key="confirm_block", type="primary", width="stretch"):
            success, err = add_to_blacklist(ip, accepted=True)
            if success:
                st.session_state.confirm_dialog_id = None
                st.session_state.block_error = None
                st.rerun()
            else:
                st.session_state.block_error = err
                st.rerun()
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
    f"<div style='text-align:right; color:var(--color-text-secondary); font-size:0.85em;'>"
    f"마지막 업데이트: {st.session_state.last_updated.strftime('%Y-%m-%d %H:%M:%S')}</div>",
    unsafe_allow_html=True,
)

# --- 공격 유형별 카운트 차트 ---
# 고정된 목록이 아니라, 현재 warnings 테이블(Attack Packet List)에 실제로 존재하는
# attack_type만 뽑아서 그래프를 그린다. 새로운 유형이 들어오면 막대가 새로 생기고,
# 더 이상 들어오지 않는 유형은 자연스럽게 그래프에서 빠진다.
present_types = sorted(df["attack_type"].dropna().unique().tolist()) if not df.empty else []

counts = df["attack_type"].value_counts()
max_counter_by_type = df.groupby("attack_type")["counter"].max()

chart_df = pd.DataFrame({
    "Attack Type": present_types,
    "Attack Count": [int(counts.get(t, 0)) for t in present_types],
    "Grade": [grade_from_counter(max_counter_by_type.get(t, 0)) for t in present_types],
})

max_count = int(chart_df["Attack Count"].max()) if len(chart_df) else 0
y_domain_max = max_count if max_count > 0 else 1
y_ticks = list(range(0, max_count + 1))

base = alt.Chart(chart_df).encode(
    x=alt.X("Attack Type", sort=present_types, title=None,
            axis=alt.Axis(labelAngle=-30)),
    y=alt.Y("Attack Count", title="Attack Count",
            scale=alt.Scale(domain=[0, y_domain_max], nice=False),
            axis=alt.Axis(values=y_ticks, format="d")),
)

bars = base.mark_bar(
    size=26, cornerRadiusTopLeft=4, cornerRadiusTopRight=4 ,
).encode(
    color=alt.Color(
        "Grade",
        scale=alt.Scale(domain=list(GRADE_COLORS.keys()), range=list(GRADE_COLORS.values())),
        legend=alt.Legend(title="Grade", orient="right"),
    ),
    tooltip=["Attack Type", "Attack Count", "Grade"],
)

labels = base.mark_text(align="center", baseline="bottom", dy=-4, color="#e6e6e6").encode(
    text=alt.Text("Attack Count:Q"),
)

chart = (
    (bars + labels)
    .properties(height=350, background="transparent")
    .configure_axis(
        labelColor="#c7cbd1",
        titleColor="#c7cbd1",
        gridColor="#2a2e37",
        domainColor="#3a3f4a",
        tickColor="#3a3f4a",
    )
    .configure_legend(
        labelColor="#c7cbd1",
        titleColor="#c7cbd1",
    )
    .configure_view(strokeWidth=0)
)

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
        grade_name = grade_from_counter(selected_row["counter"])

        st.markdown("**Detail Data View**")

        pairs = [
            ("ID", selected_row["id"]),
            ("Attack Type", selected_row["attack_type"]),
            ("Src IP", selected_row["src_ip"]),
            ("Grade", grade_badge_html(grade_name)),
            ("First Timestamp", format_ts(selected_row["first_timestamp"])),
            ("Last Timestamp", format_ts(selected_row["last_timestamp"])),
            ("Counter", selected_row["counter"]),
        ]
        st.markdown(field_grid_html(pairs, GRADE_COLORS[grade_name]), unsafe_allow_html=True)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

        # 차단은 되돌릴 수 없는 액션이므로, 버튼을 누르면 팝업으로 한 번 더 확인받는다.
        if st.button("차단하기", key="block_button", type="primary"):
            st.session_state.confirm_dialog_id = selected_row["id"]

        if st.session_state.get("confirm_dialog_id") == selected_row["id"]:
            confirm_block_dialog(selected_row)

        if selected_row["id"] in st.session_state.get("blocked_ids", set()):
            st.caption(f"차단됨: {selected_row['src_ip']}")