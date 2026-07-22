import streamlit as st

from webpages.login.accountdb import get_db

st.title("🚨 보안 알림")

if not st.session_state.get("logged_in") or st.session_state.user["role"] != "admin":
    st.error("관리자만 접근할 수 있습니다.")
    st.stop()

conn = get_db()
alerts = conn.execute(
    "SELECT id, message, created_at FROM notifications "
    "WHERE type = 'security_alert' AND is_read = 0 ORDER BY created_at DESC"
).fetchall()
conn.close()

if not alerts:
    st.info("확인하지 않은 보안 알림이 없습니다.")
else:
    st.write(f"총 **{len(alerts)}건**의 미확인 보안 알림이 있습니다.")
    st.divider()

    for a in alerts:
        col1, col2 = st.columns([5, 1])
        col1.warning(a["message"])
        col1.caption(f"발생일시: {a['created_at']}")
        if col2.button("확인", key=f"ack_{a['id']}", width="stretch"):
            conn = get_db()
            conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (a["id"],))
            conn.commit()
            conn.close()
            st.rerun()
        st.divider()
