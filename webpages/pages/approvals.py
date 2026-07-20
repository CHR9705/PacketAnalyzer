import streamlit as st

# [중요] st.set_page_config는 반드시 스크립트의 가장 첫 번째 Streamlit 명령어여야 합니다.
st.set_page_config(
    page_title="나의 대시보드",
    layout="wide"  # "centered"에서 "wide"로 변경하여 화면 가득 채움
)

from accountdb import get_db, log_action
from accountdb import get_pending_role_requests, resolve_role_request

st.title("🔔 회원가입 및 권한 관리")

# index.py의 로그인 게이트를 통과한 사용자만 이 코드까지 도달하지만,
# 혹시 모를 상황(직접 접근 등)을 대비해 한 번 더 admin 권한 체크
if not st.session_state.get("logged_in") or st.session_state.user["role"] != "admin":
    st.error("관리자만 접근할 수 있습니다.")
    st.stop()

# ----------------------------------------------------
# 데이터 불러오기 (UI 선언 전에 먼저 수행)
# ----------------------------------------------------
conn = get_db()
pending_users = conn.execute(
    "SELECT id, email, created_at FROM users WHERE status = 'pending' ORDER BY created_at"
).fetchall()
conn.close()

me = st.session_state.user
requests = get_pending_role_requests()

# ----------------------------------------------------
# 레이아웃 나누기: 화면을 5:5 비율로 양옆 분할
# ----------------------------------------------------
left_col, right_col = st.columns(2)

# ====================================================
# [왼쪽] 회원가입 승인 관리
# ====================================================
with left_col:
    st.header("👤 회원가입 승인 관리")
    
    if not pending_users:
        st.info("승인 대기중인 가입 신청이 없습니다.")
    else:
        st.write(f"총 **{len(pending_users)}건**의 승인 대기 신청이 있습니다.")
        st.divider()

        for u in pending_users:
            col1, col2, col3 = st.columns([2, 1, 1]) # 내부 버튼 정렬을 위해 좁은 영역 안에서 한번 더 나눔
            col1.write(f"**{u['email']}**")
            col1.caption(f"신청일: {u['created_at']}")

            if col2.button("✅ 승인", key=f"approve_{u['id']}", width="stretch"):
                conn = get_db()
                conn.execute("UPDATE users SET status = 'approved' WHERE id = ?", (u["id"],))
                conn.execute(
                    "UPDATE notifications SET is_read = 1 "
                    "WHERE related_user_id = ? AND type = 'signup_pending'",
                    (u["id"],),
                )
                conn.commit()
                conn.close()
                log_action(
                    "signup_approved",
                    actor_user_id=st.session_state.user["id"],
                    actor_email=st.session_state.user["email"],
                    target_user_id=u["id"],
                    detail=u["email"],
                )
                st.rerun()

            if col3.button("❌ 거절", key=f"reject_{u['id']}", width="stretch"):
                conn = get_db()
                conn.execute("UPDATE users SET status = 'rejected' WHERE id = ?", (u["id"],))
                conn.execute(
                    "UPDATE notifications SET is_read = 1 "
                    "WHERE related_user_id = ? AND type = 'signup_pending'",
                    (u["id"],),
                )
                conn.commit()
                conn.close()
                log_action(
                    "signup_rejected",
                    actor_user_id=st.session_state.user["id"],
                    actor_email=st.session_state.user["email"],
                    target_user_id=u["id"],
                    detail=u["email"],
                )
                st.rerun()

            st.divider()

# ====================================================
# [오른쪽] 권한 변경 요청 관리
# ====================================================
with right_col:
    st.header("🔑 권한 변경 요청 관리")

    if not requests:
        st.info("대기중인 권한 변경 요청이 없습니다.")
    else:
        st.write(f"총 **{len(requests)}건**의 권한 변경 요청이 대기중입니다.")
        st.divider()

        for r in requests:
            col1, col2, col3 = st.columns([2, 1, 1]) # 내부 버튼 정렬을 위해 좁은 영역 안에서 한번 더 나눔
            col1.write(f"**{r['email']}**")
            col1.caption(f"(현재: {r['current_role']}) → `{r['requested_role']}` 권한 요청")
            col1.caption(f"신청일: {r['created_at']}")

            if col2.button("✅ 승인", key=f"approve_role_{r['id']}", width="stretch"):
                ok, message = resolve_role_request(r["id"], True, me["id"], me["email"])
                if not ok:
                    st.error(message)
                st.rerun()

            if col3.button("❌ 거절", key=f"reject_role_{r['id']}", width="stretch"):
                ok, message = resolve_role_request(r["id"], False, me["id"], me["email"])
                if not ok:
                    st.error(message)
                st.rerun()

            st.divider()
