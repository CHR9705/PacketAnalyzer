import streamlit as st

def metric_cards():
    st.markdown("""
<style>
/* metric 전체 박스 - 리퀴드 글라스 */
.metric-card,
[data-testid="stMetric"] {
    position: relative;
    overflow: hidden;
    background: rgba(255, 255, 255, 0.06);
    backdrop-filter: blur(24px) saturate(160%);
    -webkit-backdrop-filter: blur(24px) saturate(160%);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 20px;
    padding: 18px 20px 16px 20px;
    margin-bottom: 4px;
    box-shadow:
        0 8px 32px rgba(0, 0, 0, 0.35),
        inset 0 1px 0 rgba(255, 255, 255, 0.25),
        inset 0 -1px 0 rgba(255, 255, 255, 0.05);
}

/* 유리 표면 반사광 (위쪽이 밝은 스펙큘러 하이라이트) */
.metric-card:before,
[data-testid="stMetric"]::before {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(
        180deg,
        rgba(255, 255, 255, 0.10) 0%,
        rgba(255, 255, 255, 0.02) 40%,
        transparent 100%
    );
    pointer-events: none;
}

/* 제목(Label) */
.metric-label,
[data-testid="stMetricLabel"] {
    color: #A8B3C1;
    margin-bottom: 4px;
}
.metric-label p,
[data-testid="stMetricLabel"] p {
    font-size: 14px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
}

/* 숫자(Value) */
.metric-value,
[data-testid="stMetricValue"] {
    font-size: 34px;
    font-weight: 800;
    color: #F5F8FC;
}

/* 변화량(Delta) */
.metric-delta,
[data-testid="stMetricDelta"] {
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)


def detail_card_styles():
    st.markdown("""
<style>
/* ===== Detail Card (리퀴드 글라스) ===== */
.detail-card {
    background: rgba(255, 255, 255, 0.06);
    backdrop-filter: blur(24px) saturate(160%);
    -webkit-backdrop-filter: blur(24px) saturate(160%);
    border: 1px solid rgba(255, 255, 255, 0.14);
    border-radius: 20px;
    overflow: hidden;
    margin-bottom: 8px;
    box-shadow:
        0 8px 32px rgba(0, 0, 0, 0.35),
        inset 0 1px 0 rgba(255, 255, 255, 0.18);
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
