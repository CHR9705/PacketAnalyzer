import streamlit as st
import sqlite3
import pandas as pd
import os
import time
import ipaddress
from contextlib import closing


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "packets.db"))

BLACKLIST_TABLE = "black_list"         
WHITELIST_TABLE = "white_list"        
IP_COLUMN = "ip" 

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False



def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn

@st.cache_resource
def get_shared_connection():
    # cache_resource ensures this only runs once per session instead of
    # opening a new leaked connection on every Streamlit rerun
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


# -----------------------------
# DB HELPERS
# -----------------------------
def search_ip(ip: str):
    """Check if an IP exists in the blacklist and/or whitelist tables."""
    with closing(get_connection()) as conn:
        bl_query = f"SELECT * FROM {BLACKLIST_TABLE} WHERE {IP_COLUMN} = ?"
        wl_query = f"SELECT * FROM {WHITELIST_TABLE} WHERE {IP_COLUMN} = ?"
        df_bl = pd.read_sql_query(bl_query, conn, params=(ip,))
        df_wl = pd.read_sql_query(wl_query, conn, params=(ip,))
    return df_bl, df_wl
 

def add_to_blacklist(ip: str, accepted: bool = False):
    try:
        conn = get_shared_connection()
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

def add_to_whitelist(ip: str, accepted: bool = False):
    try:
        conn = get_shared_connection()
        existing = conn.execute("SELECT accepted FROM white_list WHERE ip = ? LIMIT 1", (ip,)).fetchone()
        if existing:
            if existing[0] == 2:
                return False, "화이트리스트해제로 등록된 IP입니다."
            return False, "이미 화이트리스트에 등록된 IP입니다."
        conn.execute(
            "INSERT INTO white_list (timestamp, ip, accepted) VALUES (?, ?, ?)",
            (time.time(), ip, 1 if accepted else 0),
        )
        return True, None
    except Exception as e:
        return False, str(e)
 
 
def remove_from_blacklist(ip: str):
    try:
        conn = get_shared_connection()
        conn.execute("UPDATE black_list SET accepted = 2 WHERE ip = ?", (ip,))
        return True, None
    except Exception as e:
        return False, str(e)
 
 
def remove_from_whitelist(ip: str):
    try:
        conn = get_shared_connection()
        conn.execute("UPDATE white_list SET accepted = 2 WHERE ip = ?", (ip,))
        return True, None
    except Exception as e:
        return False, str(e)
 
 
def fetch_all_ips(table: str, ip_column: str = "ip", exclude_accepted_2: bool = False) -> list:
    with closing(get_connection()) as conn:
        try:
            query = f"SELECT {ip_column} FROM {table}"
            if exclude_accepted_2:
                query += " WHERE accepted != 2"
            df = pd.read_sql_query(query, conn)
            return df[ip_column].tolist()
        except Exception:
            return []


GRADE_COLORS = {
    "Critical": "#d32f2f",
    "High": "#f57c00",
    "Medium": "#fbc02d",
    "Low": "#43a047",
    "None": "#1976d2",
}
ADJUSTABLE_GRADES = ["Low", "Medium", "High", "Critical"]  # None은 score==0 고정이라 제외

def score_to_grade(score: float) -> str:
    if score <= 0:
        return "None"
    elif score < 4:
        return "Low"
    elif score < 7:
        return "Medium"
    elif score < 9:
        return "High"
    else:
        return "Critical"
 
 
def save_condition(grade: str, score: float):
    """grade(PK) 기준으로 blocked_conditions에 upsert."""
    try:
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO blocked_conditions (grade, score)
            VALUES (?, ?)
            ON CONFLICT(grade) DO UPDATE SET score = excluded.score
            """,
            (grade, score),
        )
        conn.commit()
        conn.close()
        return True, None
    except Exception as e:
        return False, str(e)
# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="IP Search", layout="wide")

from webpages.css.st_header import _setting
from webpages.css.st_glass import liquid_glass

_setting()
liquid_glass()

st.markdown("""
<h1 style="
    font-size:28px;
    margin:0;
">
Settings
</h1>
""", unsafe_allow_html=True)

st.markdown(
    """
    <style>
    .error-text {
        color: #d33; font-weight: 600; margin-top: 4px;
    }
    .success-text {
        color: #2a8a2a; font-weight: 600; margin-top: 4px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
 
if "search_status" not in st.session_state:
    st.session_state["search_status"] = None  # None | "black" | "white" | "both" | "not_found" | "empty"

def do_search(ip_value: str):
    if not ip_value.strip():
        st.session_state["search_status"] = "empty"
        return
    df_bl, df_wl = search_ip(ip_value.strip())
    in_black = not df_bl.empty
    in_white = not df_wl.empty
    if in_black and in_white:
        st.session_state["search_status"] = "both"
    elif in_black:
        st.session_state["search_status"] = "black"
    elif in_white:
        st.session_state["search_status"] = "white"
    else:
        st.session_state["search_status"] = "not_found"

# ---- Top row: search icon | IP input | block button | whitelist button ----
outer_search_col, outer_action_col = st.columns([3.5, 3.2])

# outer_search_col 내부에 검색 폼을 배치하여 우측 등급 확인 영역과 완전히 분리
with outer_search_col:
    with st.form(key="search_form", clear_on_submit=False, border=False):
        # [수정] 버튼들이 우측으로 뻗지 않도록 내부 컬럼 비율을 좌측으로 콤팩트하게 축소
        col_input, col_search, col_block, col_white = st.columns([1.5, 0.4, 0.6, 1.2])
        
        with col_search:
            search_clicked = st.form_submit_button("🔍", width="stretch") # width 지우고 가득 채우기
     
        with col_input:
            ip_input = st.text_input(
                "IP", key="ip_value", label_visibility="collapsed", placeholder="IP"
            )
     
        with col_block:
            block_clicked = st.form_submit_button("차단", width="stretch") # width 지우고 가득 채우기
     
        with col_white:
            whitelist_clicked = st.form_submit_button("화이트리스트로 추가", width="stretch") # width 지우고 가득 채우기

# ---- Handle search ----
if search_clicked:
    do_search(ip_input)

status = st.session_state["search_status"]
if status == "empty":
    st.markdown('<div class="error-text">IP를 입력해주세요.</div>', unsafe_allow_html=True)
elif status == "not_found":
    st.markdown('<div class="error-text">블랙/화이트리스트에 없습니다.</div>', unsafe_allow_html=True)
elif status == "black":
    st.markdown('<div class="error-text">블랙리스트에 등록된 IP입니다.</div>', unsafe_allow_html=True)
elif status == "white":
    st.markdown('<div class="success-text">화이트리스트에 등록된 IP입니다.</div>', unsafe_allow_html=True)
elif status == "both":
    st.markdown('<div class="error-text">블랙리스트와 화이트리스트에 모두 등록되어 있습니다.</div>', unsafe_allow_html=True)
 
# ---- Handle block / whitelist (work even without searching first) ----
if block_clicked:
    if not ip_input.strip():
        st.markdown('<div class="error-text">차단할 IP를 입력해주세요.</div>', unsafe_allow_html=True)
    elif not is_valid_ip(ip_input.strip()):
        st.markdown('<div class="error-text">올바른 IP 형식이 아닙니다.</div>', unsafe_allow_html=True)
    else:
        ok, err = add_to_blacklist(ip_input.strip())
        if ok:
            st.rerun()
        else:
            st.markdown(f'<div class="error-text">차단 실패: {err}</div>', unsafe_allow_html=True)
 
if whitelist_clicked:
    if not ip_input.strip():
        st.markdown('<div class="error-text">추가할 IP를 입력해주세요.</div>', unsafe_allow_html=True)
    elif not is_valid_ip(ip_input.strip()):
        st.markdown('<div class="error-text">올바른 IP 형식이 아닙니다.</div>', unsafe_allow_html=True)
    else:
        ok, err = add_to_whitelist(ip_input.strip())
        if ok:
            st.rerun()
        else:
            st.markdown(f'<div class="error-text">추가 실패: {err}</div>', unsafe_allow_html=True)
 
st.divider()
 
# ---- Bottom: blacklist / whitelist columns ----
left, right = st.columns(2)

 
with left:
    list_col1, list_col2 = st.columns(2)
    with list_col1:
        st.markdown("### 블랙리스트")
        bl_ips = fetch_all_ips(BLACKLIST_TABLE, exclude_accepted_2=True)
        if bl_ips:
            bl_event = st.dataframe(
                pd.DataFrame({"IP": bl_ips}),
                width='stretch',
                height=280,
                hide_index=True,
                on_select="rerun",
                selection_mode="multi-row",
                key=f"bl_table_{len(bl_ips)}",
            )
            bl_selected_rows = bl_event.selection.rows if bl_event and bl_event.selection else []
            bl_selected_ips = [bl_ips[i] for i in bl_selected_rows]
    
            if st.button(
                f"차단 해제 ({len(bl_selected_ips)}개)" if bl_selected_ips else "차단 해제",
                width='stretch',
                key="bl_remove_btn",
                disabled=len(bl_selected_ips) == 0,
            ):
                errors = []
                for ip in bl_selected_ips:
                    ok, err = remove_from_blacklist(ip)
                    if not ok:
                        errors.append(f"{ip}: {err}")
                if errors:
                    st.markdown(f'<div class="error-text">해제 실패: {"; ".join(errors)}</div>', unsafe_allow_html=True)
                else:
                    st.rerun()
        else:
            st.caption("등록된 항목이 없습니다.")
    
    with list_col2:
        st.markdown("### 화이트리스트")
        wl_ips = fetch_all_ips(WHITELIST_TABLE, exclude_accepted_2=True)
        if wl_ips:
            wl_event = st.dataframe(
                pd.DataFrame({"IP": wl_ips}),
                width='stretch',
                height=280,
                hide_index=True,
                on_select="rerun",
                selection_mode="multi-row",
                key=f"wl_table_{len(bl_ips)}",
            )
            wl_selected_rows = wl_event.selection.rows if wl_event and wl_event.selection else []
            wl_selected_ips = [wl_ips[i] for i in wl_selected_rows]
    
            if st.button(
                f"해제 ({len(wl_selected_ips)}개)" if wl_selected_ips else "해제",
                width='stretch',
                key="wl_remove_btn",
                disabled=len(wl_selected_ips) == 0,
            ):
                errors = []
                for ip in wl_selected_ips:
                    ok, err = remove_from_whitelist(ip)
                    if not ok:
                        errors.append(f"{ip}: {err}")
                if errors:
                    st.markdown(f'<div class="error-text">해제 실패: {"; ".join(errors)}</div>', unsafe_allow_html=True)
                else:
                    st.rerun()
        else:
            st.caption("등록된 항목이 없습니다.")


with right:
    st.title("🔐자동차단조건")
    if "score_value" not in st.session_state:
        st.session_state.score_value = 5.0
    
    grade = score_to_grade(st.session_state.score_value)
    color = GRADE_COLORS[grade]
    
    with st.container(key="score_slider"):
        st.slider(
            "score", min_value=0.0, max_value=10.0, step=0.1,
            key="score_value", label_visibility="collapsed",
        )
    
    # 슬라이더 중앙 하단에 등급 텍스트 표시
    st.markdown(
        f"<div style='text-align:center;font-weight:700;font-size:1.1rem;"
        f"color:{color};margin-top:0.6rem;'>{grade}</div>",
        unsafe_allow_html=True,
    )
    
    if st.button("저장", width="stretch"):
        ok, err = save_condition(grade, st.session_state.score_value)
        if ok:
            st.success(f"저장 완료: grade={grade}, score={st.session_state.score_value}")
        else:
            st.session_state["_error"] = err
    
    # 핸들(및 값 말풍선) 색상을 현재 등급 색으로 지정
    st.markdown(
        f"""
    <style>
    .st-key-score_slider div[role="slider"] {{
        background-color: {color} !important;
        border-color: {color} !important;
        box-shadow: 0 0 0 4px {color}33 !important;
    }}
    /* [수정] 상단 숫자 배경 제거, 테두리 제거, 크기 확대, 위치 조정 */
    .st-key-score_slider div[data-testid="stSliderThumbValue"] {{
        background-color: transparent !important;
        border: none !important;
        color: {color} !important;
        font-size: 1.6rem !important;
        font-weight: 700 !important;
        top: -35px !important;
    }}
    </style>
    """,
        unsafe_allow_html=True,
    )
    
    if st.session_state.get("_error"):
        st.error(f"DB 저장 실패: {st.session_state['_error']}")
        del st.session_state["_error"]

        