import streamlit as st
import streamlit.components.v1 as components
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
    """차단 해제: black_list와 blocked_packets 테이블에서
    해당 IP 기록을 실제로 삭제한다. (iptables는 아직 미구현이라 DB만 처리)"""
    try:
        conn = get_shared_connection()
        # conn.execute("DELETE FROM black_list WHERE ip = ?", (ip,))
        # conn.execute("DELETE FROM blocked_packets WHERE src_ip = ?", (ip,))
        conn.execute("UPDATE black_list SET accepted = 2  WHERE ip = ?", (ip,))
        return True, None
    except Exception as e:
        return False, str(e)


def remove_from_whitelist(ip: str):
    try:
        conn = get_shared_connection()
        # conn.execute("DELETE FROM white_list WHERE ip = ?", (ip,))
        conn.execute("UPDATE white_list SET accepted = 2  WHERE ip = ?", (ip,))
        return True, None
    except Exception as e:
        return False, str(e)


def fetch_all_ips(
    table: str,
    ip_column: str = "ip",
    exclude_accepted_2: bool = False
) -> list:

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
 
def load_condition():
    conn = get_connection()

    row = conn.execute("""
        SELECT grade, score
        FROM blocked_conditions
        LIMIT 1
    """).fetchone()

    conn.close()

    return row

def save_condition(grade: str, score: float):
    try:
        conn = get_connection()

        conn.execute("""
            UPDATE blocked_conditions
            SET grade = ?, score = ?
        """, (grade, score))

        conn.commit()
        conn.close()

        return True, None

    except Exception as e:
        return False, str(e)
# -----------------------------
# UI
# -----------------------------
st.set_page_config(
    page_title="Block Management",
    page_icon="🚫",
    layout="wide",
)

from webpages.css.st_header import _setting

_setting()

st.markdown("""<h1 style="font-size:28px; margin:0;">🚫 Block Management</h1>""", unsafe_allow_html=True)

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
    st.session_state["search_status"] = None

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
outer_search_col, outer_action_col = st.columns(2)

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
left, spacer, right = st.columns([1, 0.08, 1])

 
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
            bl_selected_ips = [bl_ips[i] for i in bl_selected_rows if 0 <= i < len(bl_ips)]
    
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
                key=f"wl_table_{len(wl_ips)}",
            )
            wl_selected_rows = wl_event.selection.rows if wl_event and wl_event.selection else []
            wl_selected_ips = [wl_ips[i] for i in wl_selected_rows if 0 <= i < len(wl_ips)]
    
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
    # 왼쪽 블랙리스트/화이트리스트 영역과 살짝 여백을 두기 위한 간격
    st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)

    st.markdown(
        """
    <h1 style="font-size:28px; margin:0;">🔐자동차단조건</h1>
    """,
        unsafe_allow_html=True,
    )
    # st.title("🔐자동차단조건")
    if "score_value" not in st.session_state:
        row = load_condition()

        if row:
            _, score = row
            st.session_state.score_value = score
        else:
            st.session_state.score_value = 5.0
    
    grade = score_to_grade(st.session_state.score_value)
    color = GRADE_COLORS[grade]
    fill_pct = st.session_state.score_value * 10  # 0~10 → 0~100%

    with st.container(key="score_slider"):
        st.slider(
            "score", min_value=0.0, max_value=10.0, step=0.1,
            key="score_value", label_visibility="collapsed",
        )
    
    # 등급 텍스트: 초기 렌더용 placeholder. 실제 위치는 아래 JS가
    # 이 요소를 핸들(thumb)의 자식으로 옮겨 붙여서, 숫자 말풍선처럼
    # 핸들에 완전히 밀착된 채로 함께 움직이게 만든다.
    st.markdown(
        f"<div class='score-grade-text' style='font-weight:700; font-size:1.1rem; "
        f"color:{color}; white-space:nowrap;'>{grade}</div>",
        unsafe_allow_html=True,
    )

    # 저장 버튼: 글자 수에 맞춰 폭을 줄이고, 우측 정렬한다.
    left_space, right_btn = st.columns([5, 1])

    with right_btn:
        st.button("저장", key="save_btn", use_container_width=True)

    if st.session_state.get("save_btn"):
        ok, err = save_condition(
            score_to_grade(st.session_state.score_value),
            st.session_state.score_value,
        )

        if ok:
            st.session_state["save_success"] = True

            if "score_value" in st.session_state:
                del st.session_state["score_value"]

            st.rerun()
        else:
            st.error(err)
    if st.session_state.pop("save_success", False):
        st.success("저장되었습니다.")
    
    # 슬라이더(핸들/트랙/값 말풍선) 색상을 현재 등급 색으로 지정.
    # Streamlit 1.60 슬라이더는 react-aria 기반이라 핸들에 role="slider"가 없고
    # 핸들/트랙에 testid도 없어서 emotion 타깃 클래스(e23vpic*)로 잡는다.
    # (스트림릿 업그레이드로 클래스명이 바뀌면 색만 기본값으로 돌아가고 동작에는 지장 없음)
    st.markdown(
        f"""
    <style>
    .st-key-score_slider {{
        position: relative !important;
    }}
    /* 핸들: 평상시엔 iOS 스타일 흰색 알약 (드래그 중 색상은 JS가 입힘) */
    .st-key-score_slider [data-testid="stSlider"] [class*="e23vpic3"] {{
        width:40px !important;
        height:24px !important;
        position:relative !important;
        top:10px !important;
        border-radius: 999px !important;
        background-color: #FFFFFF !important;
        box-shadow:
            0 1px 3px rgba(0, 0, 0, 0.35),
            0 4px 10px rgba(0, 0, 0, 0.20) !important;
        position: relative !important;
        overflow: visible !important;
    }}
    /* 트랙: 채워진 구간을 등급 색으로 다시 그린다 */
    .st-key-score_slider [data-testid="stSlider"] [class*="e23vpic5"] {{
        background: linear-gradient(
            to right,
            {color} 0%,
            {color} {fill_pct:.1f}%,
            rgba(151, 166, 195, 0.25) {fill_pct:.1f}%,
            rgba(151, 166, 195, 0.25) 100%) !important;
    }}
    /* 값 말풍선 */
    .st-key-score_slider div[data-testid="stSliderThumbValue"] {{
        background-color: transparent !important;
        border: none !important;
        color: {color} !important;
        font-size: 1.6rem !important;
        font-weight: 700 !important;
        top: -35px !important;
    }}
    /* 등급 텍스트: 핸들의 자식으로 옮겨진 뒤, 핸들 바로 아래에 딱 붙는다 */
    .score-grade-text {{
        position: absolute !important;
        top: 28px !important;
        left: 50% !important;
        transform: translateX(-50%) !important;
        pointer-events: none !important;
    }}
    /* 저장 버튼: 글자 수만큼만 폭을 차지하고, 컨테이너 안에서 오른쪽으로 정렬 */
    .st-key-save_btn_wrap {{
        display: flex !important;
        justify-content: flex-end !important;
    }}
    .st-key-save_btn_wrap [data-testid="stButton"] {{
        margin-left: auto !important;
        width: fit-content !important;
    }}
    .st-key-save_btn_wrap button {{
        width: auto !important;
        padding-left: 22px !important;
        padding-right: 22px !important;
    }}
    </style>
    """,
        unsafe_allow_html=True,
    )

    # iOS 리퀴드 글라스 핸들: 드래그하는 동안 핸들 위에 반투명 유리 렌즈가
    # 스프링 애니메이션으로 부풀어 오르고, 놓으면 원래대로 줄어든다.
    # (.glass-dragging 클래스는 아래 components.html JS가 토글)
    st.markdown(
        """
    <style>
    .st-key-score_slider [class*="e23vpic3"]::after {
        content: "";
        position: absolute;
        inset: -4px -8px;  /* 흰 알약(40x24)과 기존 렌즈(72x42)의 중간 크기(56x32) */
        border-radius: 999px;
        background: rgba(255, 255, 255, 0.12);
        backdrop-filter: blur(3px) saturate(180%) brightness(1.1);
        -webkit-backdrop-filter: blur(3px) saturate(180%) brightness(1.1);
        border: 1px solid rgba(255, 255, 255, 0.45);
        box-shadow:
            0 6px 18px rgba(0, 0, 0, 0.25),
            inset 0 1px 0 rgba(255, 255, 255, 0.55),
            inset 0 -1px 0 rgba(255, 255, 255, 0.15);
        opacity: 0;
        transform: scale(0.55);
        transition:
            opacity 0.15s ease,
            transform 0.3s cubic-bezier(0.2, 1.6, 0.4, 1);
        pointer-events: none;
    }
    .st-key-score_slider.glass-dragging [class*="e23vpic3"]::after {
        opacity: 1;
        transform: scale(1);
    }
    /* 드래그 중에는 안쪽 알약을 숨기고 트랙 선과 유리 렌즈만 보이게 */
    .st-key-score_slider.glass-dragging [class*="e23vpic3"] {
        background-color: transparent !important;
        box-shadow: none !important;
    }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # 드래그 중에는 Streamlit rerun이 없어서 CSS만으로는 색/텍스트가 실시간으로 못 바뀐다.
    # 핵심 변경: 등급 라벨(.score-grade-text)을 컨테이너 기준 left:% 로 흉내내는 대신,
    # 핸들(thumb) DOM의 자식으로 실제로 옮겨 붙인다. 이렇게 하면 값 말풍선처럼
    # 핸들과 완전히 같은 좌표계에서 움직여서, 슬라이더 안쪽 여백/폭 계산 오차 없이
    # 항상 핸들에 딱 붙어서 함께 이동한다.
    components.html(
        """
        <script>
        (function () {
            const doc = window.parent.document;
            const gradeOf = (v) =>
                v <= 0 ? ["None", "#1976d2"]
                : v < 4 ? ["Low", "#43a047"]
                : v < 7 ? ["Medium", "#fbc02d"]
                : v < 9 ? ["High", "#f57c00"]
                : ["Critical", "#d32f2f"];

            function hook() {
                const root = doc.querySelector(".st-key-score_slider");
                const input = root && root.querySelector('input[type="range"]');
                const thumb = root && root.querySelector('[class*="e23vpic3"]');
                const track = root && root.querySelector('[class*="e23vpic5"]');
                const label = doc.querySelector(".score-grade-text");
                if (!input || !thumb || !track || !label) { setTimeout(hook, 200); return; }
                const bubble = root.querySelector('[data-testid="stSliderThumbValue"]');

                // 등급 라벨을 핸들의 자식으로 한 번만 옮겨 붙인다.
                // (부모가 바뀌어도 CSS의 position:absolute; top:28px; left:50% 는 그대로 적용됨)
                if (label.parentElement !== thumb) {
                    thumb.appendChild(label);
                }

                const apply = () => {
                    const v = parseFloat(input.value);
                    if (isNaN(v)) return;
                    const [name, c] = gradeOf(v);
                    const pct = v * 10;
                    track.style.setProperty("background",
                        `linear-gradient(to right, ${c} 0%, ${c} ${pct}%, ` +
                        `rgba(151,166,195,0.25) ${pct}%, rgba(151,166,195,0.25) 100%)`,
                        "important");
                    if (bubble) bubble.style.setProperty("color", c, "important");
                    label.textContent = name;
                    label.style.setProperty("color", c, "important");
                };

                new MutationObserver(apply).observe(input, { attributes: true });
                input.addEventListener("input", apply);

                const stopDrag = () => { root.classList.remove("glass-dragging"); apply(); };
                root.addEventListener("pointerdown", () => {
                    root.classList.add("glass-dragging");
                    apply();
                });
                doc.addEventListener("pointerup", stopDrag);
                doc.addEventListener("pointercancel", stopDrag);

                apply();
            }
            hook();
        })();
        </script>
        """,
        height=0,
    )
    
    if st.session_state.get("_error"):
        st.error(f"DB 저장 실패: {st.session_state['_error']}")
        del st.session_state["_error"]