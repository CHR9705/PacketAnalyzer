import streamlit as st


def liquid_glass():
    """차트를 리퀴드 글라스 패널로 감싸고, 블러가 비칠 배경 글로우를 깐다."""
    st.markdown("""
    <style>
    /* 배경: 은은한 컬러 글로우 (글라스 블러가 비칠 대상) */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(1200px 600px at 15% -10%, rgba(37, 99, 235, 0.22), transparent 60%),
            radial-gradient(1000px 500px at 85% 10%, rgba(45, 212, 191, 0.16), transparent 60%),
            radial-gradient(800px 500px at 25% 55%, rgba(59, 130, 246, 0.13), transparent 65%),
            radial-gradient(800px 500px at 75% 65%, rgba(45, 212, 191, 0.11), transparent 65%),
            radial-gradient(900px 600px at 50% 110%, rgba(99, 102, 241, 0.14), transparent 60%),
            #0B1017;
    }

    /* Plotly / Altair 차트 - 리퀴드 글라스 패널 */
    [data-testid="stPlotlyChart"],
    [data-testid="stVegaLiteChart"] {
        position: relative;
        overflow: hidden;
        background: rgba(255, 255, 255, 0.06);
        backdrop-filter: blur(24px) saturate(160%);
        -webkit-backdrop-filter: blur(24px) saturate(160%);
        border: 1px solid rgba(255, 255, 255, 0.14);
        border-radius: 20px;
        padding: 12px 10px 6px 6px;
        box-shadow:
            0 8px 32px rgba(0, 0, 0, 0.35),
            inset 0 1px 0 rgba(255, 255, 255, 0.25),
            inset 0 -1px 0 rgba(255, 255, 255, 0.05);
    }

    /* 유리 표면 반사광 (위쪽이 밝은 스펙큘러 하이라이트) */
    [data-testid="stPlotlyChart"]::before,
    [data-testid="stVegaLiteChart"]::before {
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
        z-index: 1;
    }
    </style>
    """, unsafe_allow_html=True)
