
import streamlit as st

def colored_metric(label, value, color):
    st.markdown(f"""
    <div class="metric-card"">
        <div class="metric-label">{label}</div>
        <div class="metric-value", style="-webkit-text-fill-color:{color}">{value}</div>
    </div>
    """, unsafe_allow_html=True)