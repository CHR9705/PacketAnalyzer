import streamlit as st

def metric_cards():
    st.markdown("""
<style>
/* metric 전체 박스 */
[data-testid="stMetric"] {
    background: dimgrey;
    border: 1px solid #e6e8eb;
    border-left: 4px solid #001aff;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 4px; 
}

/* 제목(Label) */
[data-testid="stMetricLabel"] {
    font-size: 15px;
    color: #FFFFFF;
    margin-bottom: 4px;
}

/* 숫자(Value) */
[data-testid="stMetricValue"] {
    font-size: 30px;
    font-weight: 700;
    color: #001aff;
}

/* 변화량(Delta) */
[data-testid="stMetricDelta"] {
    font-size: 12px;
}
</style>
""", unsafe_allow_html=True)