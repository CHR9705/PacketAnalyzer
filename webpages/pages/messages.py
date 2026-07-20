import streamlit as st
from streamlit_autorefresh import st_autorefresh

from accountdb import get_db

st.title("💬 메시지")

if not st.session_state.get("logged_in"):
    st.error("로그인이 필요합니다.")
    st.stop()

me = st.session_state.user

# 3초마다 화면을 자동으로 다시 그려서 상대방이 보낸 새 메시지를 반영합니다.
st_autorefresh(interval=3000, key="messages_autorefresh")

conn = get_db()
others = conn.execute(
    "SELECT id, email FROM users WHERE id != ? AND status = 'approved' ORDER BY email",
    (me["id"],),
).fetchall()
conn.close()

if not others:
    st.info("대화할 수 있는 다른 사용자가 없습니다.")
    st.stop()

other_emails = [o["email"] for o in others]
selected_email = st.selectbox("대화 상대 선택", other_emails)
other = next(o for o in others if o["email"] == selected_email)

# 대화 내역 불러오기 + 상대가 보낸 메시지 읽음 처리
conn = get_db()
history = conn.execute(
    """
    SELECT sender_id, content, created_at FROM messages
    WHERE (sender_id = ? AND receiver_id = ?)
       OR (sender_id = ? AND receiver_id = ?)
    ORDER BY created_at
    """,
    (me["id"], other["id"], other["id"], me["id"]),
).fetchall()
conn.execute(
    "UPDATE messages SET is_read = 1 WHERE sender_id = ? AND receiver_id = ?",
    (other["id"], me["id"]),
)
conn.commit()
conn.close()

chat_box = st.container(height=400)
with chat_box:
    if not history:
        st.caption("아직 대화 내역이 없습니다. 첫 메시지를 보내보세요.")
    for msg in history:
        is_me = msg["sender_id"] == me["id"]
        with st.chat_message("user" if is_me else "assistant"):
            st.write(msg["content"])
            st.caption(msg["created_at"])

new_message = st.chat_input(f"{selected_email}에게 메시지 보내기")
if new_message:
    conn = get_db()
    conn.execute(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
        (me["id"], other["id"], new_message),
    )
    conn.commit()
    conn.close()
    st.rerun()
