"""
로그인/회원가입 관련 로직 전담 모듈.
index.py는 이 모듈의 require_login()만 호출해서 로그인 게이트를 처리합니다.
"""

import random
import re
import string

import streamlit as st
from captcha.image import ImageCaptcha
from werkzeug.security import generate_password_hash, check_password_hash

from webpages.login.accountdb import (
    get_db,
    create_session,
    get_user_by_session,
    delete_session,
    add_notification,
    is_locked_out,
    record_failed_login,
    record_successful_login,
    is_ip_locked_out,
    record_failed_login_ip,
    record_successful_login_ip,
    is_signup_locked_out,
    record_signup_attempt,
    is_captcha_locked_out,
    record_captcha_failure,
    record_captcha_success,
    log_action,
    update_last_login,
)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# 8자 이상 + 영문 1개 이상 + 숫자 1개 이상 (단순 길이 제한보다 강화)
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")

_CAPTCHA_CHARS = string.ascii_uppercase + string.digits
_captcha_image_gen = ImageCaptcha(width=220, height=80)


# ---------------------------------------------------------
# 이미지 캡차 (captcha 패키지, 외부 API 없이 로컬에서 생성)
# 왜곡된 문자 이미지를 직접 만들어서 OCR 없이는 못 읽게 하는 방식.
# 자동화 스크립트로 로그인/회원가입 폼에 직접 요청을 반복 전송하는 봇을 걸러내는 용도.
# ---------------------------------------------------------
def _refresh_captcha(prefix: str):
    text = "".join(random.choices(_CAPTCHA_CHARS, k=5))
    st.session_state[f"{prefix}_captcha_text"] = text


def _captcha_image(prefix: str):
    if f"{prefix}_captcha_text" not in st.session_state:
        _refresh_captcha(prefix)
    text = st.session_state[f"{prefix}_captcha_text"]
    return _captcha_image_gen.generate(text)


def _verify_captcha(prefix: str, user_input: str) -> bool:
    expected = st.session_state.get(f"{prefix}_captcha_text")
    ok = expected is not None and str(user_input).strip().upper() == expected
    _refresh_captcha(prefix)  # 시도 후엔 성공/실패 관계없이 항상 새 이미지로 교체 (재사용 방지)
    return ok


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
def signup_user(email: str, password: str, password_confirm: str, ip: str = None):
    # 0) IP 기준 회원가입 스팸/대량 생성 차단부터 확인
    locked, remaining_seconds = is_signup_locked_out(ip)
    if locked:
        remaining_min = max(1, remaining_seconds // 60)
        log_action("signup_blocked_ip_lockout", detail=f"ip={ip}")
        return False, f"짧은 시간 내 회원가입 시도가 너무 많습니다. 약 {remaining_min}분 후 다시 시도해주세요."

    record_signup_attempt(ip)

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
    log_action("signup_request", actor_email=email, target_user_id=new_user["id"], detail=f"ip={ip}")
    return True, "회원가입 신청이 완료되었습니다. 관리자 승인 후 로그인하실 수 있습니다."


def login_user(email: str, password: str, ip: str = None):
    # 1) IP 기준 잠금부터 확인 (여러 계정을 순회하는 공격 차단)
    ip_locked, ip_remaining = is_ip_locked_out(ip)
    if ip_locked:
        remaining_min = max(1, ip_remaining // 60)
        log_action("login_blocked_ip_lockout", detail=f"ip={ip}")
        return False, None, f"이 네트워크에서 반복적인 로그인 실패가 감지되어 약 {remaining_min}분간 차단되었습니다."

    # 2) 이메일 기준 잠금 확인 (비밀번호 검증 전에 차단해서 무의미한 시도 자체를 막음)
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
        record_failed_login_ip(ip)
        log_action("login_failed", actor_email=email, detail=f"ip={ip}")
        return False, None, "이메일 또는 비밀번호가 올바르지 않습니다."

    if user["status"] == "pending":
        log_action("login_blocked_pending", actor_user_id=user["id"], actor_email=email)
        return False, None, "가입 승인 대기중입니다. 관리자 승인 후 로그인해주세요."
    if user["status"] == "rejected":
        log_action("login_blocked_rejected", actor_user_id=user["id"], actor_email=email)
        return False, None, "가입이 거절되었습니다. 관리자에게 문의해주세요."

    # 로그인 성공 -> 실패 카운트 초기화(이메일+IP) + 마지막 로그인 시각 갱신 + 로그 기록
    record_successful_login(email)
    record_successful_login_ip(ip)
    last_login_at = update_last_login(user["id"])
    log_action("login_success", actor_user_id=user["id"], actor_email=email, detail=f"ip={ip}")

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
    _, center, _ = st.columns([1, 1.2, 1])
    with center:
        st.title("🔐 로그인")

        # 3회 이상 연속 실패했을 때만 캡차를 노출 (이번 세션 기준)
        fail_streak = st.session_state.get("login_fail_streak", 0)
        show_captcha = fail_streak >= 3

        with st.form("login_form", clear_on_submit=False):
            email = st.text_input("ID (이메일)", key="login_email")
            password = st.text_input("PW (비밀번호)", type="password", key="login_pw")

            captcha_input = None
            if show_captcha:
                st.image(_captcha_image("login"))
                captcha_key = f"login_captcha_{st.session_state.get('login_captcha_text', '')}"
                captcha_input = st.text_input(
                    "위 이미지의 문자를 입력하세요 (대소문자 구분 안 함)", key=captcha_key
                )

            submitted = st.form_submit_button("확인", use_container_width=True)

            if submitted:
                ip = getattr(st.context, "ip", None) or "unknown"  # 로컬 환경 등 IP 미확인 시 데모/로그용 임시 대체값
                captcha_locked, captcha_remaining = is_captcha_locked_out(ip)

                if captcha_locked:
                    remaining_min = max(1, captcha_remaining // 60)
                    st.error(f"보안 확인 시도가 너무 많습니다. 약 {remaining_min}분 후 다시 시도해주세요.")
                elif not email or not password:
                    st.warning("ID와 PW를 모두 입력해주세요.")
                elif show_captcha and not _verify_captcha("login", captcha_input):
                    record_captcha_failure(ip)
                    st.error("보안 확인 답이 올바르지 않습니다. 다시 시도해주세요.")
                else:
                    if show_captcha:
                        record_captcha_success(ip)
                    ok, user, error = login_user(email.strip().lower(), password, ip=ip)
                    if ok:
                        st.session_state.login_fail_streak = 0
                        token = create_session(user["id"])
                        st.session_state.logged_in = True
                        st.session_state.user = user
                        st.query_params["token"] = token
                        st.rerun()
                    else:
                        st.session_state.login_fail_streak = fail_streak + 1
                        st.error(error)

        if st.button("회원가입", use_container_width=True):
            st.session_state.mode = "signup"
            st.rerun()


def _render_signup():
    _, center, _ = st.columns([1, 1.2, 1])
    with center:
        st.title("📝 회원가입")

        with st.form("signup_form", clear_on_submit=False):
            email = st.text_input("ID (이메일)", key="signup_email")
            password = st.text_input("PW (8자 이상, 영문+숫자 포함)", type="password", key="signup_pw")
            password_confirm = st.text_input("PW 확인", type="password", key="signup_pw_confirm")

            st.image(_captcha_image("signup"))
            captcha_key = f"signup_captcha_{st.session_state.get('signup_captcha_text', '')}"
            captcha_input = st.text_input(
                "위 이미지의 문자를 입력하세요 (대소문자 구분 안 함)", key=captcha_key
            )

            submitted = st.form_submit_button("가입하기", use_container_width=True)

            if submitted:
                ip = getattr(st.context, "ip", None)  # 로컬 환경 등 IP 미확인 시 데모/로그용 임시 대체값
                ip = ip or "unknown" 
                captcha_locked, captcha_remaining = is_captcha_locked_out(ip)

                if captcha_locked:
                    remaining_min = max(1, captcha_remaining // 60)
                    st.error(f"보안 확인 시도가 너무 많습니다. 약 {remaining_min}분 후 다시 시도해주세요.")
                elif not _verify_captcha("signup", captcha_input):
                    record_captcha_failure(ip)
                    st.error("보안 확인 답이 올바르지 않습니다. 다시 시도해주세요.")
                else:
                    record_captcha_success(ip)
                    ok, message = signup_user(email.strip().lower(), password, password_confirm, ip=ip)
                    if ok:
                        st.success(message)
                        st.session_state.mode = "login"
                    else:
                        st.error(message)

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