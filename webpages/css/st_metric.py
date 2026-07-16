import streamlit as st


def metric_cards():
    st.markdown("""
<style>
/* metric 전체 박스 */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #1e222a 0%, #262b35 100%);
    border: 1px solid rgba(255, 255, 255, 0.06);
    border-left: 3px solid #4dabf7;
    border-radius: 14px;
    padding: 18px 22px;
    margin-bottom: 8px;
    box-shadow:
        0 4px 14px rgba(0, 0, 0, 0.35),
        -6px 0 16px -8px rgba(77, 171, 247, 0.35);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

[data-testid="stMetric"]:hover {
    transform: translateY(-2px);
    box-shadow:
        0 6px 18px rgba(0, 0, 0, 0.4),
        -6px 0 20px -6px rgba(77, 171, 247, 0.45);
}

/* 제목(Label) */
[data-testid="stMetricLabel"] {
    font-size: 13px;
    font-weight: 600;
    color: #9aa0a6;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    margin-bottom: 6px;
}

/* 숫자(Value) - 그라데이션 텍스트로 포인트 */
[data-testid="stMetricValue"] {
    font-size: 34px;
    font-weight: 800;
    background: linear-gradient(90deg, #4dabf7, #82c8ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

/* 변화량(Delta) - 알약 형태 뱃지처럼 */
[data-testid="stMetricDelta"] {
    font-size: 12px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.05);
    display: inline-block;
}
</style>
""", unsafe_allow_html=True)
 
"#010007A0"
def detail_card_styles():
    st.markdown("""
<style>
/* ===== Detail Card ===== */
.detail-card {
    background: 010007A0;
    border: 1px solid #e6e8eb;
    border-radius: 10px;
    overflow: hidden;
    margin-bottom: 8px;
}

/* ---- Header ---- */
.detail-header {
    padding: 14px 18px;
    background: linear-gradient(135deg, var(--accent-a, #001aff), var(--accent-b, #001affcc));
    color: #ffffff;
}
.detail-id-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
}
.detail-id {
    font-size: 13px;
    font-weight: 600;
    opacity: 0.9;
}
.detail-flow-line {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 16px;
    font-weight: 700;
}
.detail-flow-arrow {
    opacity: 0.8;
}

/* ---- Kind badge (packet / flow) ---- */
.kind-badge {
    font-size: 12px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 999px;
    background: rgba(255,255,255,0.18);
    color: #ffffff;
}
.kind-badge-packet {
    background: rgba(255,255,255,0.22);
}
.kind-badge-flow {
    background: rgba(255,255,255,0.22);
}

/* ---- Body ---- */
.detail-body {
    padding: 14px 18px;
}

/* 2열 그리드 배치 */
.detail-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px 16px;
    margin-bottom: 10px;
}

.detail-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 6px 8px;
    background: rgba(255,255,255,0.04);
    border-radius: 6px;
}
.detail-key {
    font-size: 11px;
    color: #a9adb3;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}
.detail-val {
    font-size: 14px;
    color: #ffffff;
    font-weight: 500;
    word-break: break-all;
}

/* ---- Badge (protocol / flags) ---- */
.badge {
    display: inline-block;
    font-size: 12px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 6px;
}
.badge-flag-empty {
    background: rgba(255,255,255,0.08);
    color: #a9adb3;
}

/* ---- Raw packet ---- */
.detail-group-title {
    font-size: 13px;
    font-weight: 700;
    color: #ffffff;
    margin: 10px 0 6px;
}
.detail-raw {
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 12px;
    color: #d1d5db;
    background: rgba(0,0,0,0.3);
    border-radius: 8px;
    padding: 10px 12px;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
}
</style>
""", unsafe_allow_html=True)