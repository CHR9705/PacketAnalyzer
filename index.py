import streamlit as st

from accountdb import init_db, get_unread_notification_count
from auth import require_login, logout

st.set_page_config(page_title="Login", page_icon="🔐", layout="centered")

init_db()

# 로그인 게이트: 로그인 안 됐으면 여기서 폼을 그리고 멈춤
require_login()

# ===========================================================
# 아래는 로그인 성공한 사용자만 도달하는 영역
# ===========================================================
me = st.session_state.user

with st.sidebar:
    st.write(f"👤 {me['email']}")
    st.write(f"권한: **{me['role']}**")
    last_login = me.get("last_login_at")
    st.caption(f"마지막 로그인: {last_login}" if last_login else "마지막 로그인: 이번이 첫 로그인입니다")
    if st.button("로그아웃"):
        logout()
    st.divider()

pages = [
    st.Page('webpages/pages/home.py', title='🏠 Home'),
    st.Page('webpages/pages/warning_list.py', title='⚠️ warnings'),
    st.Page('webpages/pages/details.py', title='details'),
    st.Page('webpages/pages/messages.py', title='💬 메시지'),
]

# 일반 유저에게는 권한 요청 페이지 노출
if me["role"] != "admin":
    pages.append(st.Page('webpages/pages/role_request.py', title='🙋 권한 요청'))

if me["role"] == "admin":
    signup_pending = get_unread_notification_count("signup_pending")
    role_pending = get_unread_notification_count("role_request")
    
    total_pending = signup_pending + role_pending

    if total_pending > 0:
        signup_label = f"🔔 가입 및 권한 승인 ({total_pending})"
        role_label = f"🛡️ 권한 요청 ({total_pending})"
    else:
        signup_label = "가입 승인 관리"
        role_label = "권한 요청 관리"

    pages.append(st.Page('webpages/pages/approvals.py', title=signup_label))

    pages.append(st.Page('webpages/pages/settings.py', title="settings"))
    pages.append(st.Page('webpages/pages/audit_log.py', title='📜 감사 로그'))

pg = st.navigation(pages)
pg.run()