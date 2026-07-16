import streamlit as st


def alret_box_style():
    st.markdown("""
    <style>
    .alert-div {
        border:1px solid #ff6969;
        border-radius:10px;
        padding:6px 10px;
        margin-bottom:4px;
        display:grid;
        grid-template-columns: 2fr 2fr 2fr 1fr;
        align-items:center;
        font-size:14px;
        color:#DC2626;
        background-color:rgba(255, 133, 133,0.1);
    }
    
    .alert-cnt-span{
        display:inline-block;
        min-width:10px;
        padding:2px 8px;
        text-align:center;
        background:#DC2626;
        color:white;
        border-radius:20px;
        font-size:12px;
        font-weight:bold;
    }
    </style>
    """, unsafe_allow_html=True)