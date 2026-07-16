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


CUSTOM_CSS = """
<style>
html, body, [class*="css"] {
    font-size: 16px;
}
.metric-card {
    background: #ffffff;
    border: 1px solid #e6e8eb;
    border-left: 4px solid #2f5bff;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 4px;
}
.metric-label {
    font-size: 15px;
    color: #6b7280;
    margin-bottom: 4px;
}
.metric-value {
    font-size: 30px;
    font-weight: 700;
    color: #2f5bff;
}
.section-title {
    font-size: 22px;
    font-weight: 700;
    margin-top: 6px;
    margin-bottom: 10px;
}
.detail-empty {
    background: linear-gradient(135deg, #eef3ff 0%, #f5f0ff 100%);
    border-radius: 12px;
    padding: 24px;
    color: #4f46e5;
    font-size: 18px;
    min-height: 120px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
}
.detail-card {
    background: #ffffff;
    border: 1px solid #e6e8eb;
    border-radius: 14px;
    padding: 0;
    overflow: hidden;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}
.detail-header {
    padding: 18px 24px;
    color: #ffffff;
    background: linear-gradient(135deg, var(--accent-a) 0%, var(--accent-b) 100%);
}
.detail-id-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 8px;
}
.detail-id {
    font-size: 14px;
    opacity: 0.85;
    font-weight: 600;
    letter-spacing: 0.5px;
}
.kind-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 0.5px;
    color: #ffffff;
    text-transform: uppercase;
}
.kind-badge-packet {
    background: #1d4ed8;
}
.kind-badge-flow {
    background: #7c3aed;
}
.detail-flow-line {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 19px;
    font-weight: 700;
    font-family: "SFMono-Regular", Consolas, monospace;
    flex-wrap: wrap;
}
.detail-flow-arrow {
    opacity: 0.8;
    font-size: 18px;
}
.detail-body {
    padding: 20px 24px 24px 24px;
}
.detail-group-title {
    font-size: 14px;
    font-weight: 700;
    color: #6b7280;
    margin: 18px 0 10px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 6px;
}
.detail-group-title:first-of-type {
    margin-top: 0;
}
.detail-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    column-gap: 28px;
}
.detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 11px 0;
    border-bottom: 1px solid #f0f1f3;
}
.detail-row:last-child {
    border-bottom: none;
}
.detail-key {
    font-size: 16px;
    color: #6b7280;
    font-weight: 500;
}
.detail-val {
    font-size: 19px;
    color: #1f2937;
    font-weight: 700;
    font-family: "SFMono-Regular", Consolas, monospace;
    text-align: right;
}
.badge {
    display: inline-block;
    padding: 5px 16px;
    border-radius: 20px;
    font-size: 15px;
    font-weight: 700;
    font-family: inherit;
}
.badge-flag-empty { background: #f3f4f6; color: #9ca3af; }
.badge-ttl { background: #f5f0ff; color: #7c3aed; }
.detail-raw {
    background: #0f172a;
    color: #67e8f9;
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 13.5px;
    padding: 14px 16px;
    border-radius: 10px;
    max-height: 160px;
    overflow: auto;
    word-break: break-all;
    line-height: 1.6;
}
hr {
    margin: 8px 0 18px 0;
}
</style>
"""