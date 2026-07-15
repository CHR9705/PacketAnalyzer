import streamlit as st
import sqlite3
import pandas as pd
import os
import time
from contextlib import closing


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.normpath(os.path.join(BASE_DIR, "..", "..", "packets.db"))

BLACKLIST_TABLE = "black_list"         
WHITELIST_TABLE = "white_list"        
IP_COLUMN = "ip"                    


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
        existing = conn.execute("SELECT 1 FROM black_list WHERE ip = ? LIMIT 1", (ip,)).fetchone()
        if existing:
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
        existing = conn.execute ("SELECT 1 FROM white_list WHERE ip = ? LIMIT 1",(ip,)).fetchone()
        if existing:
            return False, "이미 화이트리스트에 등록된 IP입니다"
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

# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="IP Search", layout="centered")


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
outer_search_col, outer_action_col = st.columns([4, 2.7])
 
with outer_search_col:
    with st.form(key="search_form", clear_on_submit=False, border=False):
        col_input, col_search  = st.columns([3, 0.7])
        with col_search:
            search_clicked = st.form_submit_button("🔍", use_container_width=True)
        with col_input:
            ip_input = st.text_input(
                "IP", key="ip_value", label_visibility="collapsed", placeholder="IP"
            )
 
with outer_action_col:
    col_block, col_white = st.columns([1.1, 1.6])
    with col_block:
        block_clicked = st.button("차단", use_container_width=True)
    with col_white:
        whitelist_clicked = st.button("화이트리스트로 추가", use_container_width=True)
 
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
    else:
        ok, err = add_to_blacklist(ip_input.strip())
        if ok:
            st.rerun()
        else:
            st.markdown(f'<div class="error-text">차단 실패: {err}</div>', unsafe_allow_html=True)
 
if whitelist_clicked:
    if not ip_input.strip():
        st.markdown('<div class="error-text">추가할 IP를 입력해주세요.</div>', unsafe_allow_html=True)
    else:
        ok, err = add_to_whitelist(ip_input.strip())
        if ok:
            st.rerun()
        else:
            st.markdown(f'<div class="error-text">추가 실패: {err}</div>', unsafe_allow_html=True)
 
st.divider()
 
# ---- Bottom: blacklist / whitelist columns ----
list_col1, list_col2 = st.columns(2)
 
with list_col1:
    st.markdown("### 블랙리스트")
    bl_ips = fetch_all_ips(BLACKLIST_TABLE, exclude_accepted_2=True)
    if bl_ips:
        bl_event = st.dataframe(
            pd.DataFrame({"IP": bl_ips}),
            use_container_width=True,
            height=280,
            hide_index=True,
            on_select="rerun",
            selection_mode="multi-row",
            key="bl_table",
        )
        bl_selected_rows = bl_event.selection.rows if bl_event and bl_event.selection else []
        bl_selected_ips = [bl_ips[i] for i in bl_selected_rows]
 
        if st.button(
            f"차단 해제 ({len(bl_selected_ips)}개)" if bl_selected_ips else "차단 해제",
            use_container_width=True,
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
            use_container_width=True,
            height=280,
            hide_index=True,
            on_select="rerun",
            selection_mode="multi-row",
            key="wl_table",
        )
        wl_selected_rows = wl_event.selection.rows if wl_event and wl_event.selection else []
        wl_selected_ips = [wl_ips[i] for i in wl_selected_rows]
 
        if st.button(
            f"해제 ({len(wl_selected_ips)}개)" if wl_selected_ips else "해제",
            use_container_width=True,
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