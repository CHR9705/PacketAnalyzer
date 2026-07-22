import streamlit as st

from webpages.login.accountdb import get_db

from  webpages.css.st_header import _setting
_setting()


# st.title("🚨 보안 알림")
st.markdown(
    """
<h1 style="font-size:28px; margin:0;">🚨 보안 알림</h1>
""",
    unsafe_allow_html=True,
)

if not st.session_state.get("logged_in") or st.session_state.user["role"] != "admin":
    st.error("관리자만 접근할 수 있습니다.")
    st.stop()

conn = get_db()
alerts = conn.execute(
    "SELECT id, type, message, created_at FROM notifications "
    "WHERE type IN ('security_alert', 'concurrent_login_attempt') AND is_read = 0 "
    "ORDER BY created_at DESC"
).fetchall()
conn.close()

if not alerts:
    st.info("확인하지 않은 보안 알림이 없습니다.")
else:
    st.write(f"총 **{len(alerts)}건**의 미확인 보안 알림이 있습니다.")
    st.divider()

    type_label = {
        "security_alert": "🔒 계정/IP 잠금",
        "concurrent_login_attempt": "👥 동시 로그인 시도",
    }

    for a in alerts:
        col1, col2 = st.columns([5, 1])
        col1.caption(type_label.get(a["type"], a["type"]))
        col1.warning(a["message"])
        col1.caption(f"발생일시: {a['created_at']}")
        if col2.button("확인", key=f"ack_{a['id']}", use_container_width=True):
            conn = get_db()
            conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (a["id"],))
            conn.commit()
            conn.close()
            st.rerun()
        st.divider()
