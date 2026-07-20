import streamlit as st


def alret_box_style():
    st.markdown("""
    <style>
    .alert-div {
        border:1px solid #E5484D;
        border-radius:10px;
        padding:8px 12px;
        margin-bottom:6px;
        display:grid;
        grid-template-columns: 2fr 2fr 2fr 1fr;
        align-items:center;
        font-size:14px;
        color:#FF6B6B;
        background-color:rgba(229, 72, 77, 0.07);
    }

    .alert-cnt-span{
        display:inline-block;
        justify-self:end;
        min-width:36px;
        padding:2px 10px;
        text-align:center;
        background:#DC2626;
        color:white;
        border-radius:20px;
        font-size:12px;
        font-weight:bold;
    }
    </style>
    """, unsafe_allow_html=True)
