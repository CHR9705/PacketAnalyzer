import pandas as pd
import plotly.express as px
import streamlit as st
import sys
from pathlib import Path
from streamlit_autorefresh import st_autorefresh

# pages 폴더의 상위 폴더(webpages)를 import 경로에 추가
sys.path.append(str(Path(__file__).resolve().parent.parent))
from _dbsource import get_ip_list_from_db, get_warnings_list_from_db
from _geoprocess import (
    ANOMALOUS_SOURCE_STATUSES,
    STATUS_LABELS,
    build_index,
    lookup_ips,
)

st.set_page_config(page_title="IP 접속 위치 대시보드", layout="wide")


REFRESH_INTERVAL_SECONDS = 5
 
st_autorefresh(interval=REFRESH_INTERVAL_SECONDS * 1000, key="auto_refresh")
 
 
@st.cache_resource
def get_index():
    return build_index()
 
@st.cache_data(ttl=REFRESH_INTERVAL_SECONDS)
def load_geo_data() -> pd.DataFrame:
    """DB에서 IP 목록을 가져와 status/위경도까지 붙인 DataFrame 반환.
    ttl을 REFRESH_INTERVAL_SECONDS와 맞춰서, 자동 새로고침 시마다 새 데이터를 반영."""
    index = get_index()
    ip_list = get_ip_list_from_db()
    warnings_list = get_warnings_list_from_db()
    return lookup_ips(index, ip_list)
 
 
st.title("IP 접속 위치 대시보드")
st.caption(f"{REFRESH_INTERVAL_SECONDS}초마다 자동으로 갱신됩니다.")
 
df = load_geo_data()
df["status_label"] = df["status"].map(STATUS_LABELS).fillna(df["status"])
 
ok_df = df[df["status"] == "ok"]
private_df = df[df["status"] == "private"]
anomalous_df = df[df["status"].isin(ANOMALOUS_SOURCE_STATUSES)]
 
# ---------------- 상단 요약 지표 ----------------
col1, col2, col3, col4 = st.columns(4)
col1.metric("총 로그 건수", len(df))
col2.metric("위치 확인(공인 IP)", len(ok_df))
col3.metric("내부망(사설 IP)", len(private_df))
col4.metric("스푸핑 의심(Class D/E)", len(anomalous_df), delta_color="inverse")
 
if len(anomalous_df) > 0:
    st.error(
        f"⚠ 출발지 IP가 멀티캐스트(Class D)/예약대역(Class E)인 로그 {len(anomalous_df)}건 발견 "
        "— 실제 트래픽에서는 나올 수 없는 대역이므로 스푸핑/패킷 조작 가능성이 있습니다."
    )
 
# ---------------- 지도 (공인 IP만) ----------------
st.subheader("Packets Receiving")
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
 
    map_tab, geo_tab, bar_tab = st.tabs(["st.map", "Plotly scatter_geo", "국가별 건수"])
 
    with map_tab:
        st.map(ok_df.rename(columns={"latitude": "lat", "longitude": "lon"}), zoom=1)
 
    with geo_tab:
        fig_geo = px.scatter_geo(
            count_df, lat="latitude", lon="longitude", size="count",
            hover_name="country_name", projection="natural earth",
        )
        st.plotly_chart(fig_geo, use_container_width=True)
 
    with bar_tab:
        fig_bar = px.bar(
            count_df, x="country_name", y="count", text="count",
        )
        st.plotly_chart(fig_bar, use_container_width=True)
 
    # ---- 국가 선택(클릭) -> 상세 정보 ----
    st.markdown("**국가를 선택하면 상세 접속 내역을 볼 수 있습니다.**")
    country_event = st.dataframe(
        count_df[["country_code", "country_name", "count"]],
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="country_table",
    )
 
    selected_rows = country_event.selection.rows if country_event.selection else []
    if selected_rows:
        selected_country = count_df.iloc[selected_rows[0]]
        st.subheader(
            f"📍 {selected_country['country_name']} ({selected_country['country_code']}) 상세"
        )
        st.metric("총 접속 건수", int(selected_country["count"]))
 
        country_ip_df = (
            ok_df[ok_df["country_code"] == selected_country["country_code"]]
            .groupby("ip")
            .size()
            .reset_index(name="접속 횟수")
            .sort_values("접속 횟수", ascending=False)
            .reset_index(drop=True)
        )
        st.dataframe(country_ip_df, use_container_width=True, hide_index=True)
 
# ---------------- IP 검색 ----------------
st.subheader("IP 검색")
search_ip = st.text_input("조회할 IP를 입력하세요 (부분 검색 가능)", value="")
 
if search_ip:
    matched_df = df[df["ip"].str.contains(search_ip, na=False)]
 
    if matched_df.empty:
        st.warning(f"'{search_ip}'에 해당하는 로그가 없습니다.")
    else:
        for ip_value, group in matched_df.groupby("ip"):
            row = group.iloc[0]
            access_count = len(group)
 
            with st.container(border=True):
                st.markdown(f"**{ip_value}** — {STATUS_LABELS.get(row['status'], row['status'])}")
                c1, c2, c3 = st.columns(3)
                c1.metric("접속 횟수", access_count)
                c2.metric("국가", row["country_name"] or "-")
                c3.metric("국가코드", row["country_code"] or "-")
                if row["status"] == "ok":
                    st.write(f"위도: {row['latitude']}, 경도: {row['longitude']}")
                    st.map(
                        pd.DataFrame({"lat": [row["latitude"]], "lon": [row["longitude"]]}),
                        zoom=3,
                    )
 
# ---------------- 상태별 분포 (사설망 / 이상 / 기타) ----------------
st.subheader("IP 상태별 분포")
status_count_df = df["status_label"].value_counts().reset_index()
status_count_df.columns = ["status_label", "count"]
fig_status = px.bar(status_count_df, x="status_label", y="count", text="count")
st.plotly_chart(fig_status, use_container_width=True)
 
# ---------------- 이상 징후(스푸핑 의심) 로그 상세 ----------------
if not anomalous_df.empty:
    st.subheader("스푸핑/조작 의심 로그 (Class D/E)")
    st.dataframe(anomalous_df[["ip", "status_label"]], use_container_width=True)
 
# ---------------- 내부망 로그 상세 ----------------
if not private_df.empty:
    st.subheader("내부망(사설 IP) 로그")
    st.dataframe(private_df[["ip", "status_label"]], use_container_width=True)
 
# ---------------- 원본 데이터 ----------------
with st.expander("전체 원본 데이터 보기"):
    st.dataframe(df, use_container_width=True)