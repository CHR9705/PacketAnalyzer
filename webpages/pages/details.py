import importlib
import os
import sys
from pathlib import Path
import pandas as pd
import plotly.graph_objects as go
import pycountry
import streamlit as st
from babel import Locale
from zoneinfo import ZoneInfo
from webpages.functions.titles  import get_h2
from webpages.css.st_header import _setting
from webpages.css.st_glass import liquid_glass

# ----------------------------------------------------------------------
# 기본 설정
# ----------------------------------------------------------------------
st.set_page_config(
    page_title="Packet Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
)

_setting()
liquid_glass()

PROTOCOL_COLORS = {
    "TCP": {"bg": "rgba(59, 130, 246, 0.18)", "fg": "#8AB4FF", "accent": "#2f5bff"},
    "UDP": {"bg": "rgba(217, 119, 6, 0.18)", "fg": "#FBBF24", "accent": "#d97706"},
    "ICMP": {"bg": "rgba(5, 150, 105, 0.18)", "fg": "#34D399", "accent": "#059669"},
}
DEFAULT_COLOR = {"bg": "#f3f4f6", "fg": "#6b7280", "accent": "#9ca3af"}

# Detail 헤더 배경색: Packet/Flow 종류 기준
KIND_ACCENT = {
    "packet": "#31a758ff",
    "flow": "#70e0db",  
}

from  webpages.css.st_metric import metric_cards, detail_card_styles
from  webpages.css.st_alertbox import alret_box_style

metric_cards()
alret_box_style()
detail_card_styles()

st.markdown(
    """
    <style>
    /* 상단 5개 KPI 카드 중 앞쪽 2개(총 Packets, 총 Flows)만 강조 */
    div[data-testid="stMetric"]:nth-of-type(1) [data-testid="stMetricValue"],
    div[data-testid="stMetric"]:nth-of-type(2) [data-testid="stMetricValue"] {
        /* color: #f87171 !important; */
    }
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-family: "Inter", sans-serif;
        font-weight: 700;
        font-size: 20px !important;
    }
    div[data-testid="stMetric"] label {
        letter-spacing: 0.3px;
        opacity: 0.75;
        font-size: 11px !important;
    }
    div[data-testid="stMetric"] {
        padding: 10px 12px !important;
    }

    .geo-note-pills {
        display: flex;
        gap: 10px;
        margin-top: 10px;
        flex-wrap: wrap;
    }
    .geo-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 13px;
        font-family: "Inter", sans-serif;
        font-weight: 600;
    }
    .geo-pill-info {
        background: rgba(59,130,246,0.15);
        color: #93c5fd;
        border: 1px solid rgba(59,130,246,0.3);
    }
    .geo-pill-warn {
        background: rgba(239,68,68,0.15);
        color: #fca5a5;
        border: 1px solid rgba(239,68,68,0.3);
    }

    hr {
        border: none;
        height: 1px;
        background: linear-gradient(90deg, rgba(148,163,184,0) 0%, rgba(148,163,184,0.35) 50%, rgba(148,163,184,0) 100%);
        margin: 20px 0;
    }

    div[data-testid="column"]:not(:first-child) {
        border-left: 1px solid rgba(148,163,184,0.12);
        padding-left: 20px !important;
    }


    /* Packets / Flows 탭 스타일 */
    button[data-baseweb="tab"] {
        font-family: "Inter", sans-serif;
        font-size: 14px;
        font-weight: 600;
        color: #94a3b8 !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #f8fafc !important;
    }
    div[data-baseweb="tab-highlight"] {
        background-color: #3b82f6 !important;
        height: 2.5px !important;
    }

    /* 데이터프레임 헤더 */
    div[data-testid="stDataFrame"] thead tr th {
        background-color: rgba(148,163,184,0.06) !important;
        color: #cbd5e1 !important;
        font-family: "Inter", sans-serif;
        font-weight: 700;
        font-size: 12.5px;
        letter-spacing: 0.3px;
        text-transform: uppercase;
    }

    /* 새로고침 버튼 */
    div[data-testid="stButton"] button {
        border-radius: 8px;
        border: 1px solid rgba(148,163,184,0.25);
        background: rgba(148,163,184,0.06);
        color: #e2e8f0;
        font-weight: 600;
        transition: all 0.15s ease;
    }
    div[data-testid="stButton"] button:hover {
        border-color: #3b82f6;
        color: #93c5fd;
        background: rgba(59,130,246,0.1);
    }

    /* 아무것도 선택 안 됐을 때 안내 카드 보강 */
    .detail-empty {
        border: 1px dashed rgba(148,163,184,0.25) !important;
        font-family: "Inter", sans-serif !important;
    }
    /* Streamlit 기본 요소 간 세로 간격 축소 (전체 페이지 공통) */
    div[data-testid="stVerticalBlock"] {
        gap: 0.5rem !important;
    }
    div[data-testid="stElementContainer"] {
        margin-bottom: 0.4rem !important;
    }

    /* Detail 타이틀과 카드가 겹치지 않도록 최소 간격 보장 */
    .section-title {
        margin-bottom: 10px !important;
        display: block;
    }
    /* 페이지 맨 아래 여백 복구 (Traffic Monitor / Detail 하단 잘림 방지) */
    section.main > div.block-container {
        padding-bottom: 5rem !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)
# detail_card_styles()가 정의하지 않는 보조 요소 스타일
st.markdown("""
<style>
html, body, [class*="css"] {
    font-size: 16px;
}
.section-title {
    font-size: 22px;
    font-weight: 700;
    margin-top: 6px;
    margin-bottom: 10px;
}
.detail-empty {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(24px) saturate(160%);
    -webkit-backdrop-filter: blur(24px) saturate(160%);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 20px;
    padding: 24px;
    color: #A8B3C1;
    font-size: 18px;
    min-height: 120px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.18);
}
.geo-note {
    color: #A8B3C1;
    font-size: 14px;
    margin-top: 6px;
}
</style>
""", unsafe_allow_html=True)


def _protocol_color(proto: str) -> dict:
    return PROTOCOL_COLORS.get(str(proto).upper(), DEFAULT_COLOR)


def _flatten_html(html: str) -> str:
    """
    st.markdown()은 줄 앞에 공백 4칸 이상이 있으면 마크다운 코드블록으로 인식해서
    HTML을 렌더링하지 않고 그대로 텍스트로 보여준다.
    보기 좋게 들여쓴 멀티라인 f-string을 한 줄씩 lstrip 해서 이 문제를 막는다.
    """
    return "\n".join(line.lstrip() for line in html.strip("\n").splitlines())


def _format_ts(value) -> str:
    """나노초 없이 초 단위까지만 보여주는 타임스탬프 포맷"""
    if isinstance(value, pd.Timestamp):
        if pd.isna(value):
            return "-"
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if value in (None, "", "nan"):
        return "-"
    return str(value)[:19]

def _display_ready(df: pd.DataFrame, ts_cols: list[str]) -> pd.DataFrame:
    """dataframe에 표시하기 전, 타임존 오프셋 없이 보기 좋은 문자열로 변환"""
    df = df.copy()
    for col in ts_cols:
        if col in df.columns:
            df[col] = df[col].apply(_format_ts)
    return df



def render_detail(row: pd.Series, kind: str = "packet") -> str:
    """선택된 packet/flow row를 컴팩트한 2열 카드 HTML로 렌더링"""
    d = row.to_dict()

    kind_badge = (
        '<span class="kind-badge kind-badge-packet">📦 Packet</span>'
        if kind == "packet"
        else '<span class="kind-badge kind-badge-flow">🔀 Flow</span>'
    )

    def badge(value, bg, fg):
        if value in (None, "", "nan"):
            return '<span class="badge badge-flag-empty">-</span>'
        return f'<span class="badge" style="background:{bg};color:{fg};">{value}</span>'

    def field_grid_html(pairs) -> str:
        """warning_list.py의 field_grid_html과 동일한 방식: 라벨은 위, 값은 아래, 2열 그리드."""
        cells = "".join(
            "<div>"
            f"<div style='color:#94a3b8; font-size:0.82em; margin-bottom:2px;'>{label}</div>"
            f"<div style='font-size:1.02em; font-weight:600; color:#f1f5f9;'>{value}</div>"
            "</div>"
            for label, value in pairs
        )
        return f"<div style='display:grid; grid-template-columns:1fr 1fr; gap:16px 24px;'>{cells}</div>"

    proto = d.get("protocol", "-")
    colors = _protocol_color(proto)
    proto_badge = badge(proto, colors["bg"], colors["fg"])
    flag_badge = badge(d.get("tcp_flags", ""), "#eef2ff", "#4f46e5")
    kind_accent = KIND_ACCENT.get(kind, DEFAULT_COLOR["accent"])

    ts_display = _format_ts(d.get("timestamp")) if kind == "packet" else _format_ts(d.get("first_seen"))
    src_ip = d.get("src_ip", "-")
    dst_ip = d.get("dst_ip", "-")
    src_port = d.get("src_port")
    dst_port = d.get("dst_port")
    src_label = f"{src_ip}   :   {src_port}" if src_port not in (None, "", "nan") else f"{src_ip}"
    dst_label = f"{dst_ip}   :   {dst_port}" if dst_port not in (None, "", "nan") else f"{dst_ip}"

    header = f"""
    <div style="background:linear-gradient(135deg, {kind_accent}26, {kind_accent}14);
         border:1px solid {kind_accent}55;
         border-radius:14px; padding:16px 20px; margin-bottom:16px;
         backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px);">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span style="color:#e2e8f0; opacity:0.85; font-size:0.85em;">#{d.get('id', '-')}</span>
            {kind_badge}
        </div>
        <div style="color:#f1f5f9; font-weight:700; font-size:1.05em; display:flex; align-items:center; gap:8px;">
            <span>{src_label}</span>
            <span style="opacity:0.7;">→</span>
            <span>{dst_label}</span>
        </div>
    </div>
    """

    pairs = []
    if kind == "packet":
        pairs = [
            ("들어온 시간", ts_display),
            ("타입", proto_badge),
            ("출발지 IP", src_ip),
            ("목적지 IP", dst_ip),
            ("출발지 포트", src_port if src_port not in (None, "", "nan") else "-"),
            ("목적지 포트", dst_port if dst_port not in (None, "", "nan") else "-"),
            ("Packet 크기", f"{d.get('packet_size', 0):,} B"),
            ("Payload 크기", f"{d.get('payload_size', 0):,} B"),
            ("TCP Flags", flag_badge),
        ]
    else:
        pairs = [
            ("타입", proto_badge),
            ("출발지 IP", src_ip),
            ("목적지 IP", dst_ip),
            ("출발지 Port", src_port if src_port not in (None, "", "nan") else "-"),
            ("목적지 Port", dst_port if dst_port not in (None, "", "nan") else "-"),
        ]
        if "packet_count" in d:
            pairs.append(("Packet 수", f'{d["packet_count"]:,}'))
        if "total_bytes" in d:
            pairs.append(("Total Bytes", f'{d["total_bytes"]:,} B'))
        if "first_seen" in d:
            pairs.append(("First Seen", _format_ts(d.get("first_seen"))))
        if "last_seen" in d:
            pairs.append(("Last Seen", _format_ts(d.get("last_seen"))))

    body_html = field_grid_html(pairs)

    raw_html = ""
    if kind == "packet" and d.get("raw_packet") not in (None, "", "nan"):
        raw_html = f"""
        <div style="margin-top:16px; color:#94a3b8; font-size:0.82em; margin-bottom:6px;">🧬 Raw Packet</div>
        <div style="font-family:monospace; font-size:0.82em; color:#cbd5e1; word-break:break-all;
             background:rgba(0,0,0,0.25); border-radius:8px; padding:10px 12px;">{d['raw_packet']}</div>
        """

    html = f"""
    <div style="border:1px solid rgba(255,255,255,0.14); border-left:4px solid {kind_accent};
         border-radius:20px; padding:20px 24px; background-color:rgba(255,255,255,0.06);
         box-shadow:0 8px 32px rgba(0,0,0,0.35), inset 0 1px 0 rgba(255,255,255,0.18);
         backdrop-filter:blur(24px) saturate(160%); -webkit-backdrop-filter:blur(24px) saturate(160%);">
        {header}
        {body_html}
        {raw_html}
    </div>
    """
    return _flatten_html(html)

# ----------------------------------------------------------------------
# 실제 DB 로더 (_dbsource.py 연동)
# ----------------------------------------------------------------------
def _import_project_module(candidates: list[str]):
    here = os.path.dirname(os.path.abspath(__file__))
    search_dirs = [here, os.path.dirname(here), os.path.dirname(os.path.dirname(here))]

    last_error = None
    for d in search_dirs:
        if d and d not in sys.path:
            sys.path.insert(0, d)
        for module_name in candidates:
            try:
                return importlib.import_module(module_name)
            except ModuleNotFoundError as e:
                last_error = e
                continue
    raise last_error or ModuleNotFoundError(f"{candidates} 모듈을 찾을 수 없습니다.")


_dbsource_mod = _import_project_module(["_dbsource", "dbsource"])
_geoprocess_mod = _import_project_module(["_geoprocess", "geoprocess"])

dbsource = _dbsource_mod.dbsource
build_index = _geoprocess_mod.build_index
lookup_ips = _geoprocess_mod.lookup_ips
STATUS_LABELS = _geoprocess_mod.STATUS_LABELS
ANOMALOUS_SOURCE_STATUSES = _geoprocess_mod.ANOMALOUS_SOURCE_STATUSES


KST = ZoneInfo("Asia/Seoul")

def _parse_timestamp_column(series: pd.Series) -> pd.Series:
    """
    timestamp 컬럼이 문자열(ISO 포맷 등)이면 그대로 파싱하고,
    숫자(유닉스 타임스탬프)면 자릿수를 보고 s/ms/us/ns 단위를 자동 판별해서 변환한다.
    DB의 시간은 UTC 기준이므로, 이를 UTC로 명시적으로 localize한 뒤
    Asia/Seoul(KST)로 변환한다.
    """
    if pd.api.types.is_numeric_dtype(series):
        sample = series.dropna()
        if sample.empty:
            parsed = pd.to_datetime(series, errors="coerce")
        else:
            magnitude = abs(float(sample.iloc[0]))
            if magnitude >= 1e17:
                unit = "ns"
            elif magnitude >= 1e14:
                unit = "us"
            elif magnitude >= 1e11:
                unit = "ms"
            else:
                unit = "s"
            parsed = pd.to_datetime(series, unit=unit, errors="coerce")
    else:
        parsed = pd.to_datetime(series, errors="coerce")

    # UTC로 명시적으로 지정 후 KST로 변환 (naive면 UTC로 간주)
    if parsed.dt.tz is None:
        parsed = parsed.dt.tz_localize("UTC")
    return parsed.dt.tz_convert(KST)


def _load_table_from_db(table_name: str) -> pd.DataFrame:
    db = dbsource()
    rows = db.fetch(table_name)
    if not rows:
        raise ValueError(f"{table_name} 테이블에 데이터가 없습니다.")

    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["timestamp"] = _parse_timestamp_column(df["timestamp"])
    if "id" not in df.columns:
        df.insert(0, "id", range(1, len(df) + 1))
    return df.sort_values("timestamp" if "timestamp" in df.columns else "id").reset_index(drop=True)


def _load_from_db() -> pd.DataFrame:
    return _load_table_from_db("packets")


def load_packets() -> pd.DataFrame:
    """
    _dbsource.py를 통해 실제 DB에서 패킷을 가져옵니다.
    실패하면 예외를 그대로 올려서 화면에 에러로 표시합니다 (mock 대체 없음).
    """
    return _load_from_db()


def load_blocked_packets() -> pd.DataFrame:
    """blocked_packets 테이블(id, timestamp, src_ip, dst_ip, protocol, packet_size, payload_size, tcp_flags)에서
    차단된 패킷을 가져옵니다."""
    return _load_table_from_db("blocked_packets")


def build_flows(df: pd.DataFrame) -> pd.DataFrame:
    """5-tuple 중 src_port는 그룹핑에서 제외 (묶지 않음), 대신 표시용으로만 보여줌"""
    group_cols = [c for c in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"] if c in df.columns]
    if not group_cols:
        return pd.DataFrame()

    agg_kwargs = {}
    count_base = "id" if "id" in df.columns else group_cols[0]
    agg_kwargs["packet_count"] = (count_base, "count")

    if "packet_size" in df.columns:
        agg_kwargs["total_bytes"] = ("packet_size", "sum")
    if "timestamp" in df.columns:
        agg_kwargs["first_seen"] = ("timestamp", "min")
        agg_kwargs["last_seen"] = ("timestamp", "max")
    if "protocol" not in group_cols and "protocol" in df.columns:
        agg_kwargs["protocol"] = ("protocol", "first")

    # src_port는 묶지는 않되, 표시용으로 종류 수 / 대표값을 뽑음
    if "src_port" in df.columns:
        agg_kwargs["src_port_count"] = ("src_port", "nunique")
        agg_kwargs["src_port_sample"] = ("src_port", "first")

    flow = df.groupby(group_cols, dropna=False).agg(**agg_kwargs).reset_index()
    flow.insert(0, "id", range(1, len(flow) + 1))

    # 화면 표시용 Src Port 컬럼 만들기 (여러 개면 "n개", 하나면 그 값)
    if "src_port_count" in flow.columns:
        flow["src_port"] = flow.apply(
            lambda r: str(r["src_port_sample"]) if r["src_port_count"] <= 1
            else f'{r["src_port_sample"]} 외 {int(r["src_port_count"]) - 1}개',
            axis=1,
        )
        flow = flow.drop(columns=["src_port_count", "src_port_sample"])
        
        

    return flow
# ============================================================================
# Geo 조회 (ipcountry.py 로직 이식) — packets_df에서 파생된 IP 목록만 사용
# ============================================================================

def get_geo_index():
    """ipv4.csv / countries.csv 기반 조회 인덱스. 무거운 작업이라 앱 당 한 번만 생성."""
    return build_index()



def load_geo_data(ip_tuple: tuple) -> pd.DataFrame:
    """IP 목록 -> status/국가/위경도가 붙은 DataFrame. packets_df에서 파생된 IP만 입력으로 받는다."""
    index = get_geo_index()
    return lookup_ips(index, list(ip_tuple))


def _safe_iso3(iso2):
    try:
        return pycountry.countries.get(alpha_2=iso2).alpha_3
    except (LookupError, AttributeError):
        return None


_KO_COUNTRY_FALLBACK = {
    "US": "미국", "KR": "대한민국", "CN": "중국", "JP": "일본", "RU": "러시아",
    "DE": "독일", "FR": "프랑스", "GB": "영국", "NL": "네덜란드", "SG": "싱가포르",
    "HK": "홍콩", "TW": "대만", "IN": "인도", "BR": "브라질", "CA": "캐나다",
    "AU": "호주", "VN": "베트남", "TH": "태국", "ID": "인도네시아", "PH": "필리핀",
    "MY": "말레이시아", "IT": "이탈리아", "ES": "스페인", "SE": "스웨덴", "NO": "노르웨이",
    "FI": "핀란드", "DK": "덴마크", "PL": "폴란드", "UA": "우크라이나", "TR": "튀르키예",
    "IE": "아일랜드", "CH": "스위스", "AT": "오스트리아", "BE": "벨기에", "PT": "포르투갈",
    "CZ": "체코", "RO": "루마니아", "GR": "그리스", "IL": "이스라엘", "AE": "아랍에미리트",
    "SA": "사우디아라비아", "EG": "이집트", "ZA": "남아프리카공화국", "MX": "멕시코",
    "AR": "아르헨티나", "CL": "칠레", "CO": "콜롬비아", "PE": "페루", "NZ": "뉴질랜드",
    "IR": "이란", "PK": "파키스탄", "BD": "방글라데시", "KZ": "카자흐스탄", "BY": "벨라루스",
    "RS": "세르비아", "HU": "헝가리", "BG": "불가리아", "HR": "크로아티아", "SK": "슬로바키아",
    "SI": "슬로베니아", "LT": "리투아니아", "LV": "라트비아", "EE": "에스토니아",
    "LU": "룩셈부르크", "IS": "아이슬란드", "CY": "키프로스", "MT": "몰타", "MC": "모나코",
    "LI": "리히텐슈타인", "IQ": "이라크", "SY": "시리아", "JO": "요르단", "KW": "쿠웨이트",
    "QA": "카타르", "OM": "오만", "BH": "바레인", "LB": "레바논", "NG": "나이지리아",
    "KE": "케냐", "MA": "모로코", "DZ": "알제리", "TN": "튀니지", "CU": "쿠바",
    "VE": "베네수엘라", "EC": "에콰도르", "BO": "볼리비아", "PY": "파라과이", "UY": "우루과이",
    "MN": "몽골", "KH": "캄보디아", "LA": "라오스", "MM": "미얀마", "NP": "네팔",
    "LK": "스리랑카", "AF": "아프가니스탄", "UZ": "우즈베키스탄", "AZ": "아제르바이잔",
    "GE": "조지아", "AM": "아르메니아", "MD": "몰도바", "AL": "알바니아", "MK": "북마케도니아",
    "BA": "보스니아 헤르체고비나", "ME": "몬테네그로", "XK": "코소보",
}


def _country_name_ko(country_code, fallback_name: str) -> str:
    """국가 코드 -> 한글 국가명. babel이 있으면 우선 사용하고, 없으면 폴백 테이블을 사용한다."""
    code = str(country_code).upper() if country_code else ""
    try:
        from babel import Locale
        name = Locale.parse("ko").territories.get(code)
        if name:
            return name
    except Exception:
        pass
    return _KO_COUNTRY_FALLBACK.get(code, fallback_name)


def px_dark_palette(n: int) -> list[str]:
    """다크 배경에서 잘 보이는 채도 높은 팔레트를 순환시켜 반환."""
    base = [
        "#3b82f6", "#ef4444", "#10b981", "#f59e0b", "#8b5cf6",
        "#06b6d4", "#ec4899", "#84cc16", "#f97316", "#14b8a6",
    ]
    return [base[i % len(base)] for i in range(n)]


def build_geo_figures(ok_df: pd.DataFrame):
    """공인 IP(ok 상태)만으로 국가별 집계 + 코로플레스 지도 / 도넛 차트를 생성 (다크 테마)."""
    count_df = (
        ok_df.groupby(["country_code", "country_name", "latitude", "longitude"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .reset_index(drop=True)
    )
    count_df["iso3_code"] = count_df["country_code"].apply(_safe_iso3)
    count_df["country_name_ko"] = count_df.apply(
        lambda r: _country_name_ko(r["country_code"], r["country_name"]), axis=1
    )

    fig_geo = go.Figure(
        data=go.Choropleth(
            locations=count_df["iso3_code"],
            locationmode="ISO-3",
            z=count_df["count"],
            text=count_df["country_name_ko"],
            colorscale=[
                [0.0, "#22c55e"],
    [0.3, "#eab308"],  
    [0.6, "#f97316"],  
    [1.0, "#ef4444"],
            ],
            marker_line_color="#f8fafc",
            marker_line_width=1,
            colorbar=dict(
                title=dict(text="Packets", side="top", font=dict(color="#94a3b8")),
                thickness=10,
                len=0.28,
                outlinewidth=0,
                orientation="v",
                x=0.02,
                xanchor="left",
                y=0.04,
                yanchor="bottom",
                tickfont=dict(color="#94a3b8"),
            ),
            hovertemplate="<b>%{text}</b><br>Packets: %{z:,}<extra></extra>",
        )
    )
    fig_geo.update_geos(
        showframe=False,
        showcoastlines=True,
        coastlinecolor="rgba(148,163,184,0.35)",
        coastlinewidth=0.6,
        fitbounds="locations",
        domain=dict(x=[0, 1], y=[0, 1]),
        projection_type="equirectangular",
        projection_scale=3.25,
        lonaxis=dict(range=[-180, 180]),
        lataxis=dict(range=[-60, 85]),
        showland=True,
        landcolor="#1e293b",
        showocean=True,
        oceancolor="#0a0f1c",
        showlakes=True,
        lakecolor="#0a0f1c",
        showcountries=True,
        countrycolor="rgba(148,163,184,0.3)",
        bgcolor="rgba(0,0,0,0)",
    )
    fig_geo.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        height=460,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", size=12, color="#e5e7eb"),
    )

    pie_df = count_df[["country_name_ko", "count"]].copy()
    total_count = pie_df["count"].sum()
    pie_df["ratio"] = pie_df["count"] / total_count

    major_df = pie_df[pie_df["ratio"] >= 0.01]
    minor_sum = pie_df[pie_df["ratio"] < 0.01]["count"].sum()

    if minor_sum > 0:
        pie_df = pd.concat(
            [
                major_df[["country_name_ko", "count"]],
                pd.DataFrame([{"country_name_ko": "기타", "count": minor_sum}]),
            ],
            ignore_index=True,
        )
    else:
        pie_df = major_df[["country_name_ko", "count"]]

    fig_pie = go.Figure(
        data=go.Pie(
            labels=pie_df["country_name_ko"],
            values=pie_df["count"],
            hole=0.6,
            pull=[0.02] * len(pie_df),
            marker=dict(
                colors=px_dark_palette(len(pie_df)),
                line=dict(color="#0f172a", width=3),
            ),
            textinfo="none",
            hovertemplate="<b>%{label}</b><br>%{value:,}건 (%{percent})<extra></extra>",
        )
    )
    fig_pie.update_layout(
        title=dict(
            text="국가별 분포",
            font=dict(size=14, color="#f1f5f9", family="Inter, sans-serif"),
            x=0.05,
        ),
        margin=dict(l=0, r=0, t=36, b=90),
        height=460,
        showlegend=True,
        legend=dict(
            orientation="h",
            font=dict(size=11, color="#e2e8f0", family="Inter, sans-serif"),
            itemwidth=30,
            traceorder="normal",
            bgcolor="rgba(0,0,0,0)",
            x=0.5,
            xanchor="center",
            y=-0.1,
            yanchor="top",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#e5e7eb"),
    )

    return fig_geo, fig_pie, count_df


# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.markdown(
    """
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:2px;">
        <span style="font-size:26px;">🛡️</span>
        <span style="font-size:26px; font-weight:800; font-family:'Inter', sans-serif; color:#f8fafc; letter-spacing:-0.3px;">상세정보</span>
    </div>
    """,
    unsafe_allow_html=True,
)

if "view_mode" not in st.session_state:
    st.session_state.view_mode = "all"  # "all" | "blocked"

mode_col1, mode_col2, _mode_spacer = st.columns([1.3, 1, 6])
with mode_col1:
    if st.button(
        "🌐 전체 트래픽",
        width="stretch",
        type="primary" if st.session_state.view_mode == "all" else "secondary",
    ):
        if st.session_state.view_mode != "all":
            st.session_state.view_mode = "all"
            st.session_state.packets_key_ver = st.session_state.get("packets_key_ver", 0) + 1
            st.session_state.flows_key_ver = st.session_state.get("flows_key_ver", 0) + 1
            st.session_state.prev_packets_sel = ()
            st.session_state.prev_flows_sel = ()
            st.rerun()
with mode_col2:
    if st.button(
        "🚫 Blocked",
        width="stretch",
        type="primary" if st.session_state.view_mode == "blocked" else "secondary",
    ):
        if st.session_state.view_mode != "blocked":
            st.session_state.view_mode = "blocked"
            st.session_state.packets_key_ver = st.session_state.get("packets_key_ver", 0) + 1
            st.session_state.flows_key_ver = st.session_state.get("flows_key_ver", 0) + 1
            st.session_state.prev_packets_sel = ()
            st.session_state.prev_flows_sel = ()
            st.rerun()

IS_BLOCKED = st.session_state.view_mode == "blocked"

st.markdown(
    f'<div style="font-size:13px; color:#94a3b8; font-family:\'Inter\', sans-serif; letter-spacing:0.3px; margin-bottom:14px;">'
    f'{"Blocked Traffic Monitoring (차단된 패킷)" if IS_BLOCKED else "Real-Time Network Traffic Monitoring"}</div>',
    unsafe_allow_html=True,
)

try:
    packets_df = load_blocked_packets() if IS_BLOCKED else load_packets()
except Exception as e:
    table_name = "blocked_packets" if IS_BLOCKED else "packets"
    st.error(
        f"❌ DB에서 {'차단된 패킷' if IS_BLOCKED else '패킷'}을 불러오지 못했습니다: {e}\n\n"
        f"_dbsource.py 위치와 packets.db의 {table_name} 테이블을 확인해주세요."
    )
    st.stop()

flows_df = build_flows(packets_df)

TOTAL_PACKETS = len(packets_df)
TCP_PACKETS = int((packets_df.get("protocol", pd.Series(dtype=str)) == "TCP").sum())
UDP_PACKETS = int((packets_df.get("protocol", pd.Series(dtype=str)) == "UDP").sum())
UNIQUE_IP = packets_df["src_ip"].nunique() if "src_ip" in packets_df.columns else 0
AVG_PACKET_SIZE = packets_df["packet_size"].mean() if "packet_size" in packets_df.columns else 0

if IS_BLOCKED:
    # 초당 차단된 수: 차단 기록의 시간 범위(첫 ~ 마지막) 기준
    if "timestamp" in packets_df.columns and len(packets_df) > 1:
        _span_sec = (packets_df["timestamp"].max() - packets_df["timestamp"].min()).total_seconds()
    else:
        _span_sec = 0
    BLOCKED_PER_SEC = (TOTAL_PACKETS / _span_sec) if _span_sec > 0 else float(TOTAL_PACKETS)

    # 가장 많이 공격당한 목적지: blocked_packets에 dst_port가 있으면 포트 기준,
    # 없으면(현재 스키마) dst_ip 기준으로 대체
    if "dst_port" in packets_df.columns and packets_df["dst_port"].notna().any():
        TOP_TARGET_LABEL = "최다 공격 Dst Port"
        TOP_TARGET_VALUE = str(packets_df["dst_port"].value_counts().idxmax())
    elif "dst_ip" in packets_df.columns and packets_df["dst_ip"].notna().any():
        TOP_TARGET_LABEL = "최다 공격 목적지 IP"
        TOP_TARGET_VALUE = str(packets_df["dst_ip"].value_counts().idxmax())
    else:
        TOP_TARGET_LABEL = "최다 공격 Dst Port"
        TOP_TARGET_VALUE = "-"
else:
    TOTAL_FLOWS = len(flows_df)
    AVG_FLOW_PACKETS = flows_df["packet_count"].mean() if "packet_count" in flows_df.columns else 0

# ----------------------------------------------------------------------
# 상단 요약 카드
# ----------------------------------------------------------------------
c1, c2, c3, c4, c5 = st.columns(5)
if IS_BLOCKED:
    card_data = [
        (c1, "총 차단된 Packets", f"{TOTAL_PACKETS:,}"),
        (c2, "초당 차단된 수", f"{BLOCKED_PER_SEC:,.2f}"),
        (c3, "차단된 TCP 수", f"{TCP_PACKETS:,}"),
        (c4, "차단된 UDP 수", f"{UDP_PACKETS:,}"),
        (c5, "Unique IP", f"{UNIQUE_IP:,}"),
    ]
else:
    card_data = [
        (c1, "총 Packets", f"{TOTAL_PACKETS:,}"),
        (c2, "총 Flows", f"{TOTAL_FLOWS:,}"),
        (c3, "TCP Packets 수", f"{TCP_PACKETS:,}"),
        (c4, "UDP Packets 수", f"{UDP_PACKETS:,}"),
        (c5, "Unique IP", f"{UNIQUE_IP:,}"),
    ]
for col, label, value in card_data:
    with col:
        st.metric(
            label,
            value)
                

st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# 요약 통계 카드 (검색/필터 자리에 배치)
# ----------------------------------------------------------------------
s1, s2 = st.columns(2)
with s1:
    st.metric(
        "평균 Packet 크기",
        f"{AVG_PACKET_SIZE:.1f}"
    )
with s2:
    if IS_BLOCKED:
        st.metric(TOP_TARGET_LABEL, TOP_TARGET_VALUE)
    else:
        st.metric(
            "평균 Flow Packets",
            f"{AVG_FLOW_PACKETS:.1f}"
        )

filtered = packets_df.copy()


# 지도 piechart ui 
if "src_ip" not in packets_df.columns:
    st.info("src_ip 컬럼이 없어 지도를 표시할 수 없습니다.")
else:
    geo_ip_tuple = tuple(packets_df["src_ip"].dropna().tolist())
    geo_df = load_geo_data(geo_ip_tuple)
    geo_df["status_label"] = geo_df["status"].map(STATUS_LABELS).fillna(geo_df["status"])

    ok_df = geo_df[geo_df["status"] == "ok"]
    private_df = geo_df[geo_df["status"] == "private"]
    anomalous_df = geo_df[geo_df["status"].isin(ANOMALOUS_SOURCE_STATUSES)]

    if ok_df.empty:
        st.info("지도에 표시할 IP 위치 정보가 없습니다.")
    else:
        fig_geo, fig_pie, count_df = build_geo_figures(ok_df)

        col_map, col_pie = st.columns([3, 1], gap="small")
        with col_map:

            st.plotly_chart(fig_geo, width="stretch", config={"displayModeBar": False})
        with col_pie:
            st.plotly_chart(fig_pie, width="stretch", config={"displayModeBar": False})

    st.markdown(
        f'<div class="geo-note-pills">'
        f'<span class="geo-pill geo-pill-info">🌎 공인 IP {TOTAL_PACKETS-len(private_df)+len(anomalous_df):,}건</span>'
        f'<span class="geo-pill geo-pill-info">🏠 사설 IP {len(private_df):,}건</span>'
        f'<span class="geo-pill geo-pill-warn">⚠️ 비정상 출발지(멀티캐스트/예약대역) {len(anomalous_df):,}건</span>'
        f'</div>',
        unsafe_allow_html=True,
    )


st.markdown("<hr/>", unsafe_allow_html=True)

# ----------------------------------------------------------------------
# Traffic Monitor  (Packets / Flows 탭 + Detail 패널)
# ----------------------------------------------------------------------
title_col, refresh_col = st.columns([8, 1])
with title_col:
    def _clear_selection_state(*keys):
        """key 자체를 삭제해서 위젯이 선택 없는 상태로 완전히 초기화되게 함"""
        for k in keys:
            if k in st.session_state:
                del st.session_state[k]

if "packets_key_ver" not in st.session_state:
    st.session_state.packets_key_ver = 0
if "flows_key_ver" not in st.session_state:
    st.session_state.flows_key_ver = 0
if "prev_packets_sel" not in st.session_state:
    st.session_state.prev_packets_sel = ()
if "prev_flows_sel" not in st.session_state:
    st.session_state.prev_flows_sel = ()
if "packets_key_ver" not in st.session_state:
    st.session_state.packets_key_ver = 0
if "flows_key_ver" not in st.session_state:
    st.session_state.flows_key_ver = 0
if "prev_packets_sel" not in st.session_state:
    st.session_state.prev_packets_sel = ()
if "prev_flows_sel" not in st.session_state:
    st.session_state.prev_flows_sel = ()

title_col, refresh_col = st.columns([8, 1])
with title_col:
    st.markdown(
        get_h2("🚫 Blocked Traffic Monitor" if IS_BLOCKED else "📦 Traffic Monitor"),
        unsafe_allow_html=True,
    )
with refresh_col:
    if st.button("🔄 새로고침", width='stretch'):
        st.session_state.packets_key_ver += 1
        st.session_state.packets_key_ver += 1
        st.session_state.flows_key_ver += 1
        st.session_state.prev_packets_sel = ()
        st.session_state.prev_flows_sel = ()
        st.rerun()

left, right = st.columns([1, 1])

packets_key = f"packets_table_{st.session_state.packets_key_ver}"
flows_key = f"flows_table_{st.session_state.flows_key_ver}"

# ---- 탭 간 선택 상호배타 처리 ----
_packets_state = st.session_state.get(packets_key)
_flows_state = st.session_state.get(flows_key)

_packets_rows_now = tuple(_packets_state["selection"]["rows"]) if _packets_state else ()
_flows_rows_now = tuple(_flows_state["selection"]["rows"]) if _flows_state else ()

_packets_changed = _packets_rows_now != st.session_state.prev_packets_sel
_flows_changed = _flows_rows_now != st.session_state.prev_flows_sel

if _packets_changed and _packets_rows_now:
    # flows 쪽 key를 바꿔서 완전히 새 위젯으로 -> 체크 확실히 풀림
    st.session_state.flows_key_ver += 1
    flows_key = f"flows_table_{st.session_state.flows_key_ver}"
    _flows_rows_now = ()
elif _flows_changed and _flows_rows_now:
    st.session_state.packets_key_ver += 1
    packets_key = f"packets_table_{st.session_state.packets_key_ver}"
    _packets_rows_now = ()

selected_rows = []
selected_df = pd.DataFrame()
selected_kind = "packet"

with left:
    tab_packets, tab_flows = st.tabs(["📄 Packets", "🔀 Flows"])

    with tab_packets:
        packets_full = filtered.reset_index(drop=True)
        show_cols = [c for c in ["id", "timestamp", "src_ip", "protocol", "tcp_flags"] if c in packets_full.columns]
        display_df = packets_full[show_cols]
        display_df = _display_ready(display_df, ts_cols=["timestamp"]) 

        event = st.dataframe(
            display_df,
            width='stretch',
            height=340,
            hide_index=True,
            on_select="rerun",
            selection_mode="single-row",
            key=packets_key,
        )
        if event is not None and event.selection.rows:
            selected_rows = event.selection.rows
            selected_df = packets_full
            selected_kind = "packet"

    with tab_flows:
        if flows_df.empty:
            st.info("Flow 데이터를 만들 수 있는 컬럼(src_ip, dst_ip 등)이 부족합니다.")
        else:
            flow_display = flows_df.reset_index(drop=True)
            flow_show_cols = [c for c in ["id", "first_seen", "src_ip", "protocol"] if c in flow_display.columns]
            flow_view = flow_display[flow_show_cols].copy()
            display_df = _display_ready(display_df, ts_cols=["timestamp"]) 

            flow_event = st.dataframe(
                flow_view,
                width="stretch",
                height=340,
                hide_index=True,
                on_select="rerun",
                selection_mode="single-row",
                key=flows_key,
            )
            if flow_event is not None and flow_event.selection.rows:
                selected_rows = flow_event.selection.rows
                selected_df = flow_display
                selected_kind = "flow"

st.session_state.prev_packets_sel = tuple(
    st.session_state.get(packets_key, {}).get("selection", {}).get("rows", [])
)
st.session_state.prev_flows_sel = tuple(
    st.session_state.get(flows_key, {}).get("selection", {}).get("rows", [])
)

with right:
    st.markdown('<div class="section-title">📄 Detail</div>', unsafe_allow_html=True)
    if selected_rows:
        row = selected_df.iloc[selected_rows[0]]
        st.markdown(render_detail(row, kind=selected_kind), unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="detail-empty">Packet 또는 Flow를 선택하세요.</div>',
            unsafe_allow_html=True,
        )
