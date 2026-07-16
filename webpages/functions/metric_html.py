
import streamlit as st

def colored_metric(label, value, color):
    st.markdown(f"""
    <div class="metric-card" style="--accent:{color};">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
    </div>
    """, unsafe_allow_html=True)