"""
로그인/회원가입 관련 로직 전담 모듈.
index.py는 이 모듈의 require_login()만 호출해서 로그인 게이트를 처리합니다.
"""

import re

import streamlit as st
from werkzeug.security import generate_password_hash, check_password_hash

from accountdb import (
    get_db,
    create_session,
    get_user_by_session,
    delete_session,
    add_notification,
    is_locked_out,
    record_failed_login,
    record_successful_login,
    log_action,
    update_last_login,
)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# 8자 이상 + 영문 1개 이상 + 숫자 1개 이상 (단순 길이 제한보다 강화)
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")


# ---------------------------------------------------------
# 세션 상태 초기화 / URL 토큰으로 로그인 복구
# ---------------------------------------------------------
def _init_auth_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "user" not in st.session_state:
        st.session_state.user = None
    if "mode" not in st.session_state:
        st.session_state.mode = "login"


def _restore_session_from_url():
    if st.session_state.logged_in:
        return
    token = st.query_params.get("token")
    if not token:
        return
    user = get_user_by_session(token)
    if user:
        st.session_state.logged_in = True
        st.session_state.user = user
    else:
        # 유효하지 않거나 만료된 토큰이면 URL에서 제거
        st.query_params.pop("token", None)


# ---------------------------------------------------------
# 회원가입 / 로그인 비즈니스 로직
# ---------------------------------------------------------
def signup_user(email: str, password: str, password_confirm: str):
    if not EMAIL_REGEX.match(email):
        return False, "올바른 이메일 형식이 아닙니다."
    if not PASSWORD_REGEX.match(password):
        return False, "비밀번호는 8자 이상이면서 영문과 숫자를 각각 1개 이상 포함해야 합니다."
    if password != password_confirm:
        return False, "비밀번호가 일치하지 않습니다."

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return False, "이미 가입된 이메일입니다."

    conn.execute(
        "INSERT INTO users (email, password_hash, role, status) VALUES (?, ?, 'user', 'pending')",
        (email, generate_password_hash(password)),
    )
    conn.commit()
    new_user = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    add_notification(
        "signup_pending",
        f"{email} 님이 회원가입 승인을 기다리고 있습니다.",
        new_user["id"],
    )
    log_action("signup_request", actor_email=email, target_user_id=new_user["id"])
    return True, "회원가입 신청이 완료되었습니다. 관리자 승인 후 로그인하실 수 있습니다."


def login_user(email: str, password: str):
    # 1) 잠금 여부부터 확인 (비밀번호 검증 전에 차단해서 무의미한 시도 자체를 막음)
    locked, remaining_seconds = is_locked_out(email)
    if locked:
        remaining_min = max(1, remaining_seconds // 60)
        log_action("login_blocked_lockout", actor_email=email)
        return False, None, f"로그인 시도가 너무 많습니다. 약 {remaining_min}분 후 다시 시도해주세요."

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if user is None or not check_password_hash(user["password_hash"], password):
        record_failed_login(email)
        log_action("login_failed", actor_email=email)
        return False, None, "이메일 또는 비밀번호가 올바르지 않습니다."

    if user["status"] == "pending":
        log_action("login_blocked_pending", actor_user_id=user["id"], actor_email=email)
        return False, None, "가입 승인 대기중입니다. 관리자 승인 후 로그인해주세요."
    if user["status"] == "rejected":
        log_action("login_blocked_rejected", actor_user_id=user["id"], actor_email=email)
        return False, None, "가입이 거절되었습니다. 관리자에게 문의해주세요."

    # 로그인 성공 -> 실패 카운트 초기화 + 마지막 로그인 시각 갱신 + 로그 기록
    record_successful_login(email)
    last_login_at = update_last_login(user["id"])
    log_action("login_success", actor_user_id=user["id"], actor_email=email)

    return True, {
        "id": user["id"],
        "email": user["email"],
        "role": user["role"],
        "last_login_at": last_login_at,
    }, None


def logout():
    if st.session_state.user:
        log_action(
            "logout",
            actor_user_id=st.session_state.user["id"],
            actor_email=st.session_state.user["email"],
        )
    delete_session(st.query_params.get("token"))
    st.session_state.logged_in = False
    st.session_state.user = None
    st.session_state.mode = "login"
    st.query_params.pop("token", None)
    st.rerun()


# ---------------------------------------------------------
# 화면 렌더링
# ---------------------------------------------------------
def _render_login():
    st.title("🔐 로그인")
    email = st.text_input("ID (이메일)", key="login_email")
    password = st.text_input("PW (비밀번호)", type="password", key="login_pw")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("확인", use_container_width=True):
            if not email or not password:
                st.warning("ID와 PW를 모두 입력해주세요.")
            else:
                ok, user, error = login_user(email.strip().lower(), password)
                if ok:
                    token = create_session(user["id"])
                    st.session_state.logged_in = True
                    st.session_state.user = user
                    st.query_params["token"] = token
                    st.rerun()
                else:
                    st.error(error)
    with col2:
        if st.button("회원가입", use_container_width=True):
            st.session_state.mode = "signup"
            st.rerun()


def _render_signup():
    st.title("📝 회원가입")
    email = st.text_input("ID (이메일)", key="signup_email")
    password = st.text_input("PW (8자 이상, 영문+숫자 포함)", type="password", key="signup_pw")
    password_confirm = st.text_input("PW 확인", type="password", key="signup_pw_confirm")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("가입하기", use_container_width=True):
            ok, message = signup_user(email.strip().lower(), password, password_confirm)
            if ok:
                st.success(message)
                st.session_state.mode = "login"
            else:
                st.error(message)
    with col2:
        if st.button("로그인으로 돌아가기", use_container_width=True):
            st.session_state.mode = "login"
            st.rerun()


# ---------------------------------------------------------
# index.py에서 호출하는 진입점
# ---------------------------------------------------------
def require_login():
    """
    로그인 게이트.
    - 로그인 안 된 상태면 로그인/회원가입 폼을 그리고 st.stop()으로 이후 코드 실행을 막습니다.
    - 로그인 된 상태면 아무것도 하지 않고 바로 반환합니다 (index.py가 이어서 실행됨).
    """
    _init_auth_state()
    _restore_session_from_url()

    if not st.session_state.logged_in:
        if st.session_state.mode == "signup":
            _render_signup()
        else:
            _render_login()
        st.stop()