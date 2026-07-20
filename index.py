import re
import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash

from accountdb import (
    init_db,
    get_db,
    create_session,
    get_user_by_session,
    delete_session,
    add_notification,
    get_unread_notification_count,
)

st.set_page_config(page_title="Login", page_icon="🔐", layout="centered")

init_db()

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# ---------------------------------------------------------
# 세션 상태 초기화
# ---------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None
if "mode" not in st.session_state:
    st.session_state.mode = "login"

# ---------------------------------------------------------
# [버그 수정] 새로고침해도 재로그인 안 하도록 세션 복구
# 로그인 성공 시 URL 쿼리 파라미터(?token=...)에 세션 토큰을 심어두고,
# 새로고침되면 st.session_state는 초기화되더라도 URL의 token은 남아있으므로
# 그 토큰으로 DB를 조회해서 로그인 상태를 되살립니다.
# ---------------------------------------------------------
if not st.session_state.logged_in:
    token = st.query_params.get("token")
    if token:
        user = get_user_by_session(token)
        if user:
            st.session_state.logged_in = True
            st.session_state.user = user
        else:
            # 유효하지 않거나 만료된 토큰이면 URL에서 제거
            st.query_params.pop("token", None)


# ---------------------------------------------------------
# 회원가입 / 로그인 함수
# ---------------------------------------------------------
def signup_user(email: str, password: str, password_confirm: str):
    if not EMAIL_REGEX.match(email):
        return False, "올바른 이메일 형식이 아닙니다."
    if len(password) < 8:
        return False, "비밀번호는 8자 이상이어야 합니다."
    if password != password_confirm:
        return False, "비밀번호가 일치하지 않습니다."

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return False, "이미 가입된 이메일입니다."

    # 가입 즉시 사용 가능한 게 아니라 'pending' 상태로 생성 -> 관리자 승인 필요
    conn.execute(
        "INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, 'user', 'pending')",
        (email, generate_password_hash(password)),
    )
    conn.commit()
    new_user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    # 관리자에게 알림 전송 (관리자 화면의 '승인 관리' 페이지에서 확인 가능)
    add_notification(
        "signup_pending",
        f"{email} 님이 회원가입 승인을 기다리고 있습니다.",
        new_user["id"],
    )
    return True, "회원가입 신청이 완료되었습니다. 관리자 승인 후 로그인하실 수 있습니다."


def login_user(email: str, password: str):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        return False, None, "이메일 또는 비밀번호가 올바르지 않습니다."
    if user["status"] == "pending":
        return False, None, "가입 승인 대기중입니다. 관리자 승인 후 로그인해주세요."
    if user["status"] == "rejected":
        return False, None, "가입이 거절되었습니다. 관리자에게 문의해주세요."

    return True, {"id": user["id"], "email": user["email"], "role": user["role"]}, None


# ---------------------------------------------------------
# 로그인 / 회원가입 화면
# ---------------------------------------------------------
def render_login():
    st.title("🔐 로그인")
    email = st.text_input("ID (이메일)", key="login_email")
    password = st.text_input("PW (비밀번호)", type="password", key="login_pw")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("확인", width="stretch"):
            if not email or not password:
                st.warning("ID와 PW를 모두 입력해주세요.")
            else:
                ok, user, error = login_user(email.strip().lower(), password)
                if ok:
                    token = create_session(user["id"])
                    st.session_state.logged_in = True
                    st.session_state.user = user
                    st.query_params["token"] = token  # 새로고침 대비
                    st.rerun()
                else:
                    st.error(error)
    with col2:
        if st.button("회원가입", width="stretch"):
            st.session_state.mode = "signup"
            st.rerun()


def render_signup():
    st.title("📝 회원가입")
    email = st.text_input("ID (이메일)", key="signup_email")
    password = st.text_input("PW (8자 이상)", type="password", key="signup_pw")
    password_confirm = st.text_input("PW 확인", type="password", key="signup_pw_confirm")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("가입하기", width="stretch"):
            ok, message = signup_user(email.strip().lower(), password, password_confirm)
            if ok:
                st.success(message)
                st.session_state.mode = "login"
            else:
                st.error(message)
    with col2:
        if st.button("로그인으로 돌아가기", width="stretch"):
            st.session_state.mode = "login"
            st.rerun()


# ===========================================================
# 1) 로그인 게이트: 로그인 안 됐으면 여기서 멈춤
# ===========================================================
if not st.session_state.logged_in:
    if st.session_state.mode == "signup":
        render_signup()
    else:
        render_login()
    st.stop()


# ===========================================================
# 2) 로그인 이후 영역
# ===========================================================
with st.sidebar:
    st.write(f"👤 {st.session_state.user['email']}")
    st.write(f"권한: **{st.session_state.user['role']}**")
    if st.button("로그아웃"):
        delete_session(st.query_params.get("token"))
        st.session_state.logged_in = False
        st.session_state.user = None
        st.session_state.mode = "login"
        st.query_params.pop("token", None)
        st.rerun()
    st.divider()

pages = [
    st.Page('webpages/pages/home.py', title='🏠 Home'),
    st.Page('webpages/pages/warning_list.py', title='⚠️ warnings'),
    st.Page('webpages/pages/details.py', title='details'),
    st.Page('webpages/pages/messages.py', title='💬 메시지'),
]

# admin만 회원가입 승인 페이지 접근 가능
if st.session_state.user["role"] == "admin":
    pending_count = get_unread_notification_count()
    label = f"🔔 승인 대기 ({pending_count})" if pending_count else "승인 관리"
    pages.append(st.Page('webpages/pages/approvals.py', title=label))
    pages.append(st.Page('webpages/pages/settings.py', title='settings'))

pg = st.navigation(pages)
pg.run()