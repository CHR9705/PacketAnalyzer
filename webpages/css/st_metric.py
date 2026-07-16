import streamlit as st


def metric_cards():
    st.markdown("""
<style>
/* metric 전체 박스 */
.metric-card,
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
.metric-label
[data-testid="stMetricLabel"] {
    font-size: 13px;
    font-weight: 600;
    color: #9aa0a6;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    margin-bottom: 6px;
}

/* 숫자(Value) - 그라데이션 텍스트로 포인트 */
.metric-value
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