import pandas as pd
import plotly.express as px
import plotly.graph_objects as go 
import streamlit as st
import sys
from pathlib import Path
from streamlit_autorefresh import st_autorefresh
import pycountry

# pages 폴더의 상위 폴더(webpages)를 import 경로에 추가
sys.path.append(str(Path(__file__).resolve().parent.parent))
from _dbsource import dbsource 
db = dbsource() 

from _geoprocess import (
    ANOMALOUS_SOURCE_STATUSES,
    STATUS_LABELS,
    build_index,
    lookup_ips,
)

st.set_page_config(page_title="IP 접속 위치 대시보드", layout="wide")

REFRESH_INTERVAL_SECONDS = 5
 
st_autorefresh(interval=REFRESH_INTERVAL_SECONDS * 1000, key="auto_refresh")
st.markdown(
    """
    <style>
    .block-container { padding-left: 1rem; padding-right: 1rem; }
    </style>
    """,
    unsafe_allow_html=True,
) 
 
@st.cache_resource
def get_index():
    return build_index()
 
@st.cache_data(ttl=REFRESH_INTERVAL_SECONDS)
def load_geo_data() -> pd.DataFrame:
    """DB에서 IP 목록을 가져와 status/위경도까지 붙인 DataFrame 반환.
    ttl을 REFRESH_INTERVAL_SECONDS와 맞춰서, 자동 새로고침 시마다 새 데이터를 반영."""
    index = get_index()
    ip_list = db.column("packets", "src_ip")
    #warnings_list = get_warnings_list_from_db()
    return lookup_ips(index, ip_list)
 
 
df = load_geo_data()
df["status_label"] = df["status"].map(STATUS_LABELS).fillna(df["status"])
 
ok_df = df[df["status"] == "ok"]
private_df = df[df["status"] == "private"]
anomalous_df = df[df["status"].isin(ANOMALOUS_SOURCE_STATUSES)]
 
 
# ---------------- 지도 (공인 IP만) ----------------
if ok_df.empty:
    st.info("지도에 표시할 IP 위치 정보가 없습니다.")
else:
    count_df = (
        ok_df.groupby(["country_code", "country_name", "latitude", "longitude"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )
    # 2. Global converter function
    def safe_iso3(iso2):
        try:
            return pycountry.countries.get(alpha_2=iso2).alpha_3
        except (LookupError, AttributeError):
            return None

    count_df["iso3_code"] = count_df["country_code"].apply(safe_iso3)

    # geoIP settings
    fig_geo = go.Figure(
        data=go.Choropleth(
            locations=count_df["iso3_code"],
            locationmode="ISO-3",  # DB에 ISO-3 코드가 없어도 국가명으로 매칭
            z=count_df["count"],
            text=count_df["iso3_code"],
            colorscale=[
                [0.0, "#fde8e8"],
                [0.3, "#f8b4b4"],
                [0.6, "#f05252"],
                [1.0, "#9b1c1c"],
            ],
            marker_line_color="rgba(255,255,255,0.6)",
            marker_line_width=0.5,
            colorbar=dict(# 지도 범례
    title=dict(text="Packets", side="top"),
    thickness=10,
    len=0.28,
    outlinewidth=0,
    orientation="v",   
    x=0.02,            # 지도 왼쪽 끝
    xanchor="left",
    y=0.04,            # 지도 아래쪽
    yanchor="bottom",
),
            hovertemplate="<b>%{text}</b><br>Packets: %{z:,}<extra></extra>",
        )
    )
    fig_geo.update_geos(
        showframe=False,
        showcoastlines=False,
        lataxis_range=[-58, 85],
        domain=dict(x=[0, 0.9], y=[0, 1]),
        projection_type="equirectangular",
        showland=True,
        landcolor="#d6e6fc",
        showocean=True,
        oceancolor="#ffffff",
        showcountries=True,
        countrycolor="rgba(200,200,200,0.4)",
        bgcolor="rgba(0,0,0,0)",
    )
    fig_geo.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        height=500,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", size=12, color="#374151"),
    )
    TOP_N = 6
    pie_df = count_df[["country_name", "count"]].copy()
    total_count = pie_df["count"].sum()
    pie_df["ratio"] = pie_df["count"] / total_count
 
    major_df = pie_df[pie_df["ratio"] >= 0.01]
    minor_sum = pie_df[pie_df["ratio"] < 0.01]["count"].sum()
 
    if minor_sum > 0:
        pie_df = pd.concat(
            [
                major_df[["country_name", "count"]],
                pd.DataFrame([{"country_name": "Others", "count": minor_sum}]),
            ],
            ignore_index=True,
        )
    else:
        pie_df = major_df[["country_name", "count"]]
 
    fig_pie = go.Figure(
        data=go.Pie(
            labels=pie_df["country_name"],
            values=pie_df["count"],
            hole=0.55,  # 도넛 형태
            marker=dict(line=dict(color="#ffffff", width=2)),
            textinfo="none",  # 조각 위 텍스트는 생략, 대신 hover로만 표시
            hovertemplate="<b>%{label}</b><br>%{value:,}건 (%{percent})<extra></extra>",
        )
    )
    fig_pie.update_layout(
        title=dict(text="Top Countries", font=dict(size=13, color="#374151")),
        margin=dict(l=0, r=0, t=30, b=0),
        height=500,
        showlegend=True,
        legend=dict(orientation="v", font=dict(size=11)),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#374151"),
    )
 
    col_map, col_pie = st.columns([3, 1], gap="small")  # 지도 : 파이차트 비율 (필요시 숫자 조절)
    with col_map:
        # width="stretch" → 고정 px 대신 컬럼(화면) 너비에 맞춰 자동으로 늘었다 줄었다 함
        st.plotly_chart(fig_geo, width="stretch", config={"displayModeBar": False})
    with col_pie:
        st.plotly_chart(fig_pie, width="stretch", config={"displayModeBar": False})
 
    
    # ---- 국가 선택(클릭) -> 상세 정보 ----
    # st.markdown("**국가를 선택하면 상세 접속 내역을 볼 수 있습니다.**")
    # country_event = st.dataframe(
    #     count_df[["country_code", "country_name", "count"]],
    #     width="stretch",
    #     hide_index=True,
    #     on_select="rerun",
    #     selection_mode="single-row",
    #     key="country_table",
    # )
 
    # selected_rows = country_event.selection.rows if country_event.selection else []
    # if selected_rows:
    #     selected_country = count_df.iloc[selected_rows[0]]
    #     st.subheader(
    #         f"📍 {selected_country['country_name']} ({selected_country['country_code']}) 상세"
    #     )
    #     st.metric("총 접속 건수", int(selected_country["count"]))
 
    #     country_ip_df = (
    #         ok_df[ok_df["country_code"] == selected_country["country_code"]]
    #         .groupby("ip")
    #         .size()
    #         .reset_index(name="접속 횟수")
    #         .sort_values("접속 횟수", ascending=False)
    #         .reset_index(drop=True)
    #     )
    #     st.dataframe(country_ip_df, width="stretch", hide_index=True)
 
# ---------------- IP 검색 ----------------
# st.subheader("IP 검색")
# search_ip = st.text_input("조회할 IP를 입력하세요 (부분 검색 가능)", value="")
 
# if search_ip:
#     matched_df = df[df["ip"].str.contains(search_ip, na=False)]
 
#     if matched_df.empty:
#         st.warning(f"'{search_ip}'에 해당하는 로그가 없습니다.")
#     else:
#         for ip_value, group in matched_df.groupby("ip"):
#             row = group.iloc[0]
#             access_count = len(group)
 
#             with st.container(border=True):
#                 st.markdown(f"**{ip_value}** — {STATUS_LABELS.get(row['status'], row['status'])}")
#                 c1, c2, c3 = st.columns(3)
#                 c1.metric("접속 횟수", access_count)
#                 c2.metric("국가", row["country_name"] or "-")
#                 c3.metric("국가코드", row["country_code"] or "-")
#                 if row["status"] == "ok":
#                     st.write(f"위도: {row['latitude']}, 경도: {row['longitude']}")
#                     st.map(
#                         pd.DataFrame({"lat": [row["latitude"]], "lon": [row["longitude"]]}),
#                         zoom=3,
#                     )
 
# ---------------- 상태별 분포 (사설망 / 이상 / 기타) ----------------
# st.subheader("IP 상태별 분포")
# status_count_df = df["status_label"].value_counts().reset_index()
# status_count_df.columns = ["status_label", "count"]
# fig_status = px.bar(status_count_df, x="status_label", y="count", text="count")
# st.plotly_chart(fig_status, width="stretch")
 
# # ---------------- 이상 징후(스푸핑 의심) 로그 상세 ----------------
# if not anomalous_df.empty:
#     st.subheader("스푸핑/조작 의심 로그 (Class D/E)")
#     st.dataframe(anomalous_df[["ip", "status_label"]], width="stretch")
 
# # ---------------- 내부망 로그 상세 ----------------
# if not private_df.empty:
#     st.subheader("내부망(사설 IP) 로그")
#     st.dataframe(private_df[["ip", "status_label"]], width="stretch")
 
