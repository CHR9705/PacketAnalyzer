"""
Packet Analyzer Dashboard - Streamlit UI (mock data 버전)

실제 DB(dbsource.py)를 연결하려면 load_packets() 함수 안의
mock 데이터 생성 부분을 dbsource.fetch(...) 호출로 교체하면 됩니다.

실행:
    streamlit run packet_dashboard.py
"""

import random
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

# ----------------------------------------------------------------------
# 기본 설정
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="Packet Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
)

CUSTOM_CSS = """
<style>
html, body, [class*="css"] {
    font-size: 16px;
}
.metric-card {
    background: #ffffff;
    border: 1px solid #e6e8eb;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 4px;
}
.metric-label {
    font-size: 15px;
    color: #6b7280;
    margin-bottom: 4px;
}
.metric-value {
    font-size: 30px;
    font-weight: 700;
    color: #2f5bff;
}
.section-title {
    font-size: 22px;
    font-weight: 700;
    margin-top: 6px;
    margin-bottom: 10px;
}
.detail-empty {
    background: #eef3ff;
    border-radius: 10px;
    padding: 24px;
    color: #2f5bff;
    font-size: 18px;
    min-height: 120px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
}
.detail-card {
    background: #ffffff;
    border: 1px solid #e6e8eb;
    border-radius: 12px;
    padding: 22px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
}
.detail-id {
    font-size: 17px;
    color: #9aa3af;
    font-weight: 600;
    letter-spacing: 0.3px;
    margin-bottom: 2px;
}
.detail-group-title {
    font-size: 15px;
    font-weight: 700;
    color: #6b7280;
    margin: 20px 0 12px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.detail-group-title:first-of-type {
    margin-top: 4px;
}
.detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 0;
    border-bottom: 1px solid #f0f1f3;
}
.detail-row:last-child {
    border-bottom: none;
}
.detail-key {
    font-size: 17px;
    color: #6b7280;
    font-weight: 500;
}
.detail-val {
    font-size: 20px;
    color: #1f2937;
    font-weight: 700;
    font-family: "SFMono-Regular", Consolas, monospace;
}
.badge {
    display: inline-block;
    padding: 5px 16px;
    border-radius: 20px;
    font-size: 16px;
    font-weight: 700;
    font-family: inherit;
}
.badge-tcp { background: #e6f0ff; color: #2f5bff; }
.badge-udp { background: #fff1e0; color: #d97706; }
.badge-flag { background: #eef2ff; color: #4f46e5; }
.badge-flag-empty { background: #f3f4f6; color: #9ca3af; }
hr {
    margin: 8px 0 18px 0;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


def render_detail(row: pd.Series) -> str:
    """선택된 packet/flow row를 그룹핑된 카드 HTML로 렌더링"""
    d = row.to_dict()

    def badge(value, css_class):
        text = value if value not in (None, "") else "-"
        cls = css_class if value not in (None, "") else "badge badge-flag-empty"
        return f'<span class="{cls}">{text}</span>'

    proto = d.get("protocol", "")
    proto_badge = badge(proto, "badge badge-tcp" if proto == "TCP" else "badge badge-udp")
    flag_badge = badge(d.get("tcp_flags", ""), "badge badge-flag")

    rows_html = []

    def add_row(label, value_html):
        rows_html.append(
            f'<div class="detail-row"><span class="detail-key">{label}</span>'
            f'<span class="detail-val">{value_html}</span></div>'
        )

    html = f'<div class="detail-card"><div class="detail-id">ID #{d.get("id", "-")}</div>'

    html += '<div class="detail-group-title">기본 정보</div>'
    rows_html = []
    add_row("Timestamp", d.get("timestamp", "-"))
    add_row("Src IP", d.get("src_ip", "-"))
    if "dst_ip" in d:
        add_row("Dst IP", d.get("dst_ip", "-"))
    add_row("Protocol", proto_badge)
    html += "".join(rows_html)

    html += '<div class="detail-group-title">패킷 정보</div>'
    rows_html = []
    if "packet_size" in d:
        add_row("Packet Size", f'{d["packet_size"]:,} B')
    if "payload_size" in d:
        add_row("Payload Size", f'{d["payload_size"]:,} B')
    if "total_bytes" in d:
        add_row("Total Bytes", f'{d["total_bytes"]:,} B')
    if "packet_count" in d:
        add_row("Packet Count", f'{d["packet_count"]:,}')
    add_row("TCP Flags", flag_badge)
    if "first_seen" in d:
        add_row("First Seen", d.get("first_seen", "-"))
    if "last_seen" in d:
        add_row("Last Seen", d.get("last_seen", "-"))
    html += "".join(rows_html)

    html += "</div>"
    return html


# ----------------------------------------------------------------------
# Mock 데이터 로더  (추후 dbsource.py 연동 지점)
# ----------------------------------------------------------------------
@st.cache_data
def load_packets(n: int = 5000) -> pd.DataFrame:
    random.seed(42)
    protocols = ["TCP", "UDP"]
    tcp_flag_pool = ["A", "PA", "FA", "FPA", "RA", "SA", ""]
    ip_pool = [
        "192.168.1.10", "192.168.1.23", "35.219.12.4",
        "150.1.55.2", "10.0.0.5", "8.8.8.8",
    ]

    rows = []
    start = datetime(2026, 7, 15, 9, 0, 0)
    for i in range(1, n + 1):
        proto = random.choice(protocols)
        pkt_size = random.randint(54, 1500)
        payload_size = max(0, pkt_size - random.randint(20, 60))
        flags = random.choice(tcp_flag_pool) if proto == "TCP" else ""
        src_ip, dst_ip = random.sample(ip_pool, 2)
        rows.append(
            {
                "id": i,
                "timestamp": start + timedelta(milliseconds=random.randint(0, 5_000_000)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "packet_size": pkt_size,
                "payload_size": payload_size,
                "tcp_flags": flags,
            }
        )
    df = pd.DataFrame(rows)
    return df.sort_values("timestamp").reset_index(drop=True)


@st.cache_data
def build_flows(df: pd.DataFrame) -> pd.DataFrame:
    """src_ip + protocol 기준 간단 집계로 flow 테이블 생성"""
    flow = (
        df.groupby(["src_ip", "protocol"])
        .agg(
            flow_id=("id", "count"),
            packet_count=("id", "count"),
            total_bytes=("packet_size", "sum"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )
    flow.insert(0, "id", range(1, len(flow) + 1))
    flow = flow.drop(columns=["flow_id"])
    return flow


packets_df = load_packets()
flows_df = build_flows(packets_df)

TOTAL_PACKETS = len(packets_df)
TOTAL_FLOWS = len(flows_df)
TCP_PACKETS = int((packets_df["protocol"] == "TCP").sum())
UDP_PACKETS = int((packets_df["protocol"] == "UDP").sum())
UNIQUE_IP = packets_df["src_ip"].nunique()
AVG_PACKET_SIZE = packets_df["packet_size"].mean()
AVG_FLOW_PACKETS = flows_df["packet_count"].mean()


# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.markdown("## 🛡️ Packet Analyzer Dashboard")
st.caption("Real-Time Network Traffic Monitoring")

# ----------------------------------------------------------------------
# 상단 요약 카드 (Warning 카드 제거, 5개만 표시)
# ----------------------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)
card_data = [
    (c1, "Total Packets", f"{TOTAL_PACKETS:,}"),
    (c2, "Flows", f"{TOTAL_FLOWS:,}"),
    (c3, "TCP Packets", f"{TCP_PACKETS:,}"),
    (c4, "UDP Packets", f"{UDP_PACKETS:,}"),
    (c5, "Unique IP", f"{UNIQUE_IP:,}"),
]
for col, label, value in card_data:
    with col:
        st.markdown(
            f"""<div class="metric-card">
                    <div class="metric-label">{label}</div>
                    <div class="metric-value">{value}</div>
                </div>""",
            unsafe_allow_html=True,
        )

st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# 요약 통계 카드 (검색/필터 자리에 배치)
# ----------------------------------------------------------------------
s1, s2 = st.columns(2)
with s1:
    st.markdown(
        f"""<div class="metric-card">
                <div class="metric-label">Average Packet Size</div>
                <div class="metric-value">{AVG_PACKET_SIZE:.1f} B</div>
            </div>""",
        unsafe_allow_html=True,
    )
with s2:
    st.markdown(
        f"""<div class="metric-card">
                <div class="metric-label">Average Flow Packets</div>
                <div class="metric-value">{AVG_FLOW_PACKETS:.1f}</div>
            </div>""",
        unsafe_allow_html=True,
    )

filtered = packets_df.copy()

st.caption(f"Packets : {len(filtered):,} | Flows : {TOTAL_FLOWS:,}")

st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# Traffic Monitor  (Packets / Flows 탭 + Detail 패널)
# ----------------------------------------------------------------------
st.markdown('<div class="section-title">📦 Traffic Monitor</div>', unsafe_allow_html=True)

left, right = st.columns([2, 1])

with left:
    tab_packets, tab_flows = st.tabs(["📄 Packets", "🔀 Flows"])

    with tab_packets:
        # 테이블에는 5개 컬럼만 표시 (Detail에서 전체 필드 확인)
        packets_full = filtered.reset_index(drop=True)  # 전체 컬럼 보존 (Detail용)
        display_df = packets_full[["id", "timestamp", "src_ip", "protocol", "tcp_flags"]]

        event = st.dataframe(
            display_df,
            use_container_width=True,
            height=380,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="packets_table",
        )
        selected_kind = "packet"
        selected_rows = event.selection.rows if event is not None else []
        # Detail은 전체 컬럼(packets_full)에서 조회
        selected_df = packets_full

    with tab_flows:
        flow_display = flows_df.reset_index(drop=True)
        flow_event = st.dataframe(
            flow_display,
            use_container_width=True,
            height=380,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key="flows_table",
        )
        # Flows 탭이 활성화된 상태에서 선택된 경우를 우선 반영
        if flow_event is not None and flow_event.selection.rows:
            selected_kind = "flow"
            selected_rows = flow_event.selection.rows
            selected_df = flow_display

with right:
    st.markdown('<div class="section-title">📄 Detail</div>', unsafe_allow_html=True)
    if selected_rows:
        row = selected_df.iloc[selected_rows[0]]
        st.markdown(render_detail(row), unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="detail-empty">Packet 또는 Flow를 선택하세요.</div>',
            unsafe_allow_html=True,
        )