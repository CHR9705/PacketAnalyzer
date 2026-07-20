import sqlite3
import time
from datetime import datetime, timedelta, timezone
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from webpages.css.st_alertbox import alret_box_style
from webpages.css.st_header import _setting
from webpages.css.st_metric import metric_cards
from webpages.functions.titles import get_h2

from webpages.functions.titles  import get_h2
from webpages.functions.metric_html import  colored_metric
import base64
import io
import time
import asyncio
import streamlit.components.v1 as components
import edge_tts

kst = timezone(timedelta(hours=9))

# 1초마다 자동으로 화면을 새로고침하여 최신 패킷 갱신
st_autorefresh(interval=1 * 1000, key="home_refresh")
from  webpages.css.st_header import _setting
from  webpages.css.st_metric import metric_cards
from  webpages.css.st_alertbox import alret_box_style
from  webpages.css.st_glass import liquid_glass

st.set_page_config(page_title="Packet Analyzer", layout="wide")

conn = sqlite3.connect("packets.db")
_setting()

st.markdown(
    """
<h1 style="font-size:28px; margin:0;">Home</h1>
""",
    unsafe_allow_html=True,
)

########################################################
# 최근 60초 데이터 및 경고 데이터 가져오기
########################################################
now = int(datetime.now().timestamp())
start = now - 60
one_day_ago = int((datetime.now() - timedelta(days=1)).timestamp())

packets = pd.read_sql_query(
    """
SELECT *
FROM packets
WHERE timestamp >= ?
""",
    conn,
    params=(start,),
)

warnings = pd.read_sql_query(
    """
SELECT *
FROM warnings
ORDER BY last_timestamp DESC
LIMIT 5
""",
    conn,
)

warnings_cnt = pd.read_sql_query(
    """
SELECT count(*) as cnt
FROM warnings
""",
    conn,
)

blacklist_cnt = pd.read_sql_query("""
SELECT count(*) as cnt
FROM black_list
""", conn)

blocked_cnt = pd.read_sql_query("""
SELECT count(*) as cnt
FROM blocked_packets
WHERE timestamp >= ?                                
""", conn, params=(now - 60*60,))

VOICE_MAP = {
    "female": "ko-KR-SunHiNeural",
    "male": "ko-KR-InJoonNeural",
}

if "alert_voice_gender" not in st.session_state:
    st.session_state.alert_voice_gender = "female"

async def _generate_tts(text: str, voice: str) -> bytes:
    communicate = edge_tts.Communicate(text, voice)
    mp3_fp = io.BytesIO()
    async for chunk in communicate.stream():
        if chunk["type"] == "audio":
            mp3_fp.write(chunk["data"])
    mp3_fp.seek(0)
    return mp3_fp.read()

# def check_new_warning():
#     if warnings is None or warnings.empty:
#         return

#     latest_ts = warnings["last_timestamp"].iloc[0]
#     now_ts = time.time()

#     if "last_flashed_ts" not in st.session_state:
#         st.session_state.last_flashed_ts = None

#     is_new = (
#         (now_ts - latest_ts)
#     ) < 5 and latest_ts != st.session_state.last_flashed_ts
################################################################
def check_new_warning():
    current_warnings = (
        st.session_state.mock_warnings
        if "mock_warnings" in st.session_state
        else warnings
    )
    if current_warnings is None or current_warnings.empty:
        return

    latest_ts = current_warnings["last_timestamp"].iloc[0]
    now_ts = time.time()

    if "last_flashed_ts" not in st.session_state:
        st.session_state.last_flashed_ts = None

    is_new = (
        (now_ts - latest_ts)
    ) < 5 and latest_ts != st.session_state.last_flashed_ts
####################################################################
    if is_new:
        st.session_state.last_flashed_ts = latest_ts

        # 1. 붉은 화면 섬광 CSS 효과 (기존과 동일, 그대로 둠)
        st.markdown("""
        <style>
        @keyframes flash-red-fade {
            0%   { opacity: 0.55; }
            100% { opacity: 0; }
        }
        .flash-overlay {
            position: fixed;
            top: 0; left: 0;
            width: 100vw; height: 100vh;
            background-color: red;
            pointer-events: none;
            z-index: 999999;
            animation: flash-red-fade 1s ease-out forwards;
        }
        </style>
        <div class="flash-overlay"></div>
        """, unsafe_allow_html=True)

        # attack_type = warnings["attack_type"].iloc[0]
        attack_type = current_warnings["attack_type"].iloc[0]
        alert_text = f"긴급 경고. {attack_type} 공격 발생. 긴급 경고. {attack_type} 공격 발생."

        # 2. 구글 TTS 기본 오디오 바이너리 생성
        selected_voice = VOICE_MAP.get(st.session_state.alert_voice_gender, VOICE_MAP["female"])
        audio_bytes = asyncio.run(_generate_tts(alert_text, voice=selected_voice))

        # 3. 배속 재생 (여기부터 교체된 부분)
        try:
            b64_audio = base64.b64encode(audio_bytes).decode()
            speed_factor = 1.4

            components.html(
                f"""
                <script>
                (function() {{
                    const doc = window.parent.document;
                    const old = doc.getElementById("speedy-alert-audio");
                    if (old) {{ old.remove(); }}

                    const audio = doc.createElement("audio");
                    audio.id = "speedy-alert-audio";
                    audio.autoplay = true;
                    audio.style.display = "none";
                    audio.src = "data:audio/mp3;base64,{b64_audio}";
                    doc.body.appendChild(audio);

                    function applySpeed() {{
                        audio.playbackRate = {speed_factor};
                        audio.preservesPitch = false;
                    }}
                    audio.addEventListener("loadedmetadata", applySpeed);
                    audio.addEventListener("canplay", applySpeed);
                    audio.addEventListener("play", applySpeed);
                    audio.play().then(applySpeed).catch((e) => console.log("autoplay blocked:", e));
                    setTimeout(applySpeed, 100);
                    setTimeout(applySpeed, 300);

                    audio.addEventListener("ended", () => audio.remove());
                }})();
                </script>
                """,
                height=0,
            )
        except Exception as e:
            st.error(f"알람 재생 실패: {e}")




metric_cards()
liquid_glass()




# packet_size 합계 (바이트 단위라고 가정)
total_bytes = packets["packet_size"].sum()

# 경고 탐지 로직 실행
check_new_warning()

########################################################
# 대시보드 KPI 및 그래프 영역 (기존 코드 유지)
########################################################
metric_cards()
total_bytes = packets["packet_size"].sum()
bps = (total_bytes * 8) / 60

# 엔진 상태
engine_status = "Running" if packets["timestamp"].max() + 5 > now else "Stopped"

col, col1, col2, col3 = st.columns(4)

red = "#DC2626"
green = "#10B981"

# with st.container(key = "nowtime-metric"):
with col:
    colored_metric("현재 시각", datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'white')



with col1:
    color = ""
    if engine_status == "Running":
        color = green
    else:
        color = red
    colored_metric("엔진 상태", engine_status, color)

with col2:
    colored_metric("차단 IP 수", blacklist_cnt['cnt'].iloc[0], red)

with col3:
    colored_metric("1시간 이내 차단된 패킷 수", blocked_cnt['cnt'].iloc[0], red)




col1, col2, col3, col4, col5 = st.columns(5)


with col1:
    st.metric("분당 패킷 수", len(packets))
with col2:
    st.metric("PPS", round(len(packets) / 60, 1))
with col3:
    st.metric("BPS", f"{bps/1000:.1f} Kbps")
with col4:
    colored_metric("Warnings", warnings_cnt['cnt'].iloc[0], red)

with col5:
    st.metric("활성 IP", packets["src_ip"].nunique() if not packets.empty else 0)

traffic = packets.copy()

traffic["second"] = traffic["timestamp"].astype(int)

traffic["time"] = pd.to_datetime(
    traffic["second"],
    unit="s"
)

traffic = (
    traffic
    .set_index("time")
    .resample("1s")
    .size()
    .reset_index(name="Packets")
)

fig = px.line(
    traffic,
    x="time",
    y="Packets",
    markers=True
)

fig.update_traces(
    line=dict(color="#4FC3F7", width=2.5),
    marker=dict(size=5, color="#B3E5FC"),
    fill="tozeroy",
    fillcolor="rgba(79, 195, 247, 0.18)",
)

fig.update_layout(
    height = 200,
    margin=dict(l=20, r=20, t=20, b=20),
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
)

st.plotly_chart(fig, width='stretch')




left, right = st.columns(2)
with left:
    st.markdown(get_h2("프로토콜 비율"), unsafe_allow_html=True)

    proto = (
        packets["protocol"]
        .value_counts()
        .reset_index()
    )

    proto.columns = ["Protocol", "Count"]


    fig = px.bar(
        proto,
        x="Count",
        y="Protocol",
        orientation="h",
        color="Protocol",
        text="Count",
        color_discrete_map={
            "TCP": "#4A90E2",
            "UDP": "#2EC4A5",
            "OTHER": "#8B95A5"
        }
    )

    # cliponaxis=False : 막대 끝 텍스트가 플롯 영역 밖으로 나가도 잘리지 않음
    fig.update_traces(textposition="outside", cliponaxis=False)

    # 막대가 가장 길 때도 숫자가 들어갈 자리가 생기도록 x축에 여유를 준다
    if len(proto):
        fig.update_xaxes(range=[0, proto["Count"].max() * 1.18])

    fig.update_layout(
        xaxis_title="Packets",
        yaxis_title=None,
        height=200,
        showlegend=False,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    st.plotly_chart(fig, width="stretch")

  
alret_box_style()
with right:
    st.markdown(get_h2("최근 경고"), unsafe_allow_html=True)
    if warnings.empty:
        st.success("No Warning")
    else:
        for _, row in warnings.iterrows():
            last_time = datetime.fromtimestamp(
                row.last_timestamp, tz=kst
            ).strftime("%Y-%m-%d %H:%M:%S")
            st.markdown(
                f"""
            <div class="alert-div">
                <span>{row.attack_type}</span>
                <span>{row.src_ip}</span>
                <span>{last_time}</span>
                <span class="alert-cnt-span">{row.counter}</span>
            </div>
            """,
                unsafe_allow_html=True,
            )

left, right = st.columns(2)
with left:
    st.markdown(get_h2("최다 IP"), unsafe_allow_html=True)
    if not packets.empty:
        top = (
            packets.groupby("src_ip")
            .size()
            .reset_index(name="Packets")
            .sort_values("Packets", ascending=False)
            .head(5)
            .rename(columns={"src_ip": "Source IP"})
        )
        st.dataframe(top, hide_index=True, width="stretch")

with right:
    st.markdown(get_h2("최근 패킷"), unsafe_allow_html=True)
    if not packets.empty:
        recent = packets.sort_values("timestamp", ascending=False).head(5).copy()
        recent["Time"] = (
            pd.to_datetime(recent["timestamp"], unit="s", utc=True)
            .dt.tz_convert("Asia/Seoul")
            .dt.strftime("%Y-%m-%d %H:%M:%S")
        )
        recent = recent.rename(
            columns={
                "src_ip": "Source IP",
                "dst_ip": "Destination IP",
                "protocol": "Protocol",
                "packet_size": "Size (B)",
            }
        )
        st.dataframe(
            recent[["Time", "Source IP", "Destination IP", "Protocol", "Size (B)"]],
            hide_index=True,
            width="stretch",
        )

st.sidebar.subheader("🔊 경보 음성 설정")
voice_col1, voice_col2 = st.sidebar.columns(2)
with voice_col1:
    if st.button(
        "👩 여성" + (" ✅" if st.session_state.alert_voice_gender == "female" else ""),
        use_container_width=True,
    ):
        st.session_state.alert_voice_gender = "female"
        st.rerun()
with voice_col2:
    if st.button(
        "👨 남성" + (" ✅" if st.session_state.alert_voice_gender == "male" else ""),
        use_container_width=True,
    ):
        st.session_state.alert_voice_gender = "male"
        st.rerun()

# # ========================================================
# # 🧪 [테스트 전용] 완벽히 연동되는 가상 공격 트리거 버튼
# # ========================================================
# st.sidebar.subheader("🧪 TTS 알람 테스트 베드")

# # 테스트하고 싶은 공격 유형 선택박스
# test_attack = st.sidebar.selectbox(
#     "테스트할 공격 선택", ["syn flood", "port scan", "ddos", "sql injection"]
# )

# # 트리거 작동 버튼
# if st.sidebar.button("🚨 가상 공격 트리거 (테스트)"):
#     import pandas as pd

#     # 1. 현재 시각 타임스탬프(epoch) 생성
#     current_time_epoch = time.time()

#     # 2. 가상 경고 데이터 행 생성
#     new_row = pd.DataFrame(
#         {"last_timestamp": [current_time_epoch], "attack_type": [test_attack]}
#     )

#     # 3. 세션 상태(st.session_state)에 가상 데이터 영구 보존 및 병합
#     if "mock_warnings" not in st.session_state:
#         st.session_state.mock_warnings = pd.concat(
#             [new_row, warnings], ignore_index=True
#         )
#     else:
#         st.session_state.mock_warnings = pd.concat(
#             [new_row, st.session_state.mock_warnings], ignore_index=True
#         )

#     # 4. 주입 성공 메시지 출력 후 화면을 즉시 강제 새로고침(rerun)
#     st.sidebar.success(f"'{test_attack}' 데이터 주입 성공!")
#     st.rerun()

