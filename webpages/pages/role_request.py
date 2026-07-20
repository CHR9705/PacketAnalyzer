import streamlit as st

from accountdb import create_role_request, get_my_role_requests

st.title("🙋 권한 변경 요청")

if not st.session_state.get("logged_in"):
    st.error("로그인이 필요합니다.")
    st.stop()

me = st.session_state.user

if me["role"] == "admin":
    st.info("이미 관리자 권한을 가지고 있습니다.")
    st.stop()

st.write(f"현재 권한: **{me['role']}**")
st.write("관리자 권한이 필요하시면 아래 버튼으로 요청하실 수 있습니다. 관리자가 승인하면 즉시 반영됩니다.")

my_requests = get_my_role_requests(me["id"], limit=5)
has_pending = any(r["status"] == "pending" for r in my_requests)

if has_pending:
    st.warning("이미 처리 대기중인 요청이 있습니다. 관리자 승인을 기다려주세요.")
else:
    if st.button("🙋 관리자 권한 요청하기"):
        ok, message = create_role_request(me["id"], "admin")
        if ok:
            st.success(message)
            st.rerun()
        else:
            st.error(message)

if my_requests:
    st.divider()
    st.subheader("내 요청 내역")
    status_label = {"pending": "⏳ 대기중", "approved": "✅ 승인됨", "rejected": "❌ 거절됨"}
    for r in my_requests:
        st.write(
            f"- **{r['requested_role']}** 권한 요청 — {status_label.get(r['status'], r['status'])} "
            f"(신청일: {r['created_at']})"
        )