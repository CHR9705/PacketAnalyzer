import streamlit as st


def _setting():
    st.markdown("""
    <style>
    header[data-testid="stHeader"] {
        background: transparent;
        height: 2rem;  /* 필요시 높이 줄이기 */
    }
    /* Deploy 버튼만 숨기기 */
    [data-testid="stAppDeployButton"] {
        display: none;
    }

    /* 우측 상단 메뉴(⋮) 숨기기 */
    #MainMenu {
        visibility: hidden;
    }

    /* 상단 여백 제거 */
    .block-container {
        padding-top: 1rem;
        padding-bottom: 0rem;
    }

    /* 하단 푸터 숨기기 */
    footer {
        visibility: hidden;
    }
    </style>
    """, unsafe_allow_html=True)