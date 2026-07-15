
import bisect
import ipaddress
from dataclasses import dataclass

import pandas as pd

IPV4_CSV_PATH = "webpages/ipv4.csv"
COUNTRIES_CSV_PATH = "webpages/countries.csv"

# 지도에 찍을 수 있는(=위경도가 존재하는) 정상 상태
OK_STATUS = "ok"

# 사람이 읽기 좋은 상태 라벨 (대시보드 표시용)
STATUS_LABELS = {
    "ok": "정상 위치확인",
    "private": "내부망(사설 IP)",
    "multicast": "멀티캐스트(Class D) - 비정상 출발지",
    "reserved": "예약대역(Class E) - 비정상 출발지",
    "invalid": "잘못된 IP 형식",
    "not_found": "국가 매칭 실패",
    "no_coords": "국가는 찾았으나 좌표 없음",
}

# 실제 인터넷 트래픽의 "출발지"로는 나올 수 없는, 스푸핑/조작 의심 상태
ANOMALOUS_SOURCE_STATUSES = {"multicast", "reserved"}


@dataclass
class GeoIPIndex:
    """이진 탐색용으로 정렬/인덱싱된 IP 대역 데이터 + 국가별 좌표 테이블"""
    start_list: list
    end_list: list
    country_list: list
    countries_df: pd.DataFrame
    iso_col: str
    lat_col: str
    lon_col: str
    name_col: str | None


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str:
    """df.columns 중 candidates 후보군과 일치하는 컬럼명을 찾아 반환.
    못 찾으면 실제 컬럼 목록을 포함한 에러를 발생시킴."""
    for name in candidates:
        if name in df.columns:
            return name
    raise KeyError(
        f"{candidates} 중 일치하는 컬럼을 찾을 수 없습니다. "
        f"실제 컬럼: {df.columns.tolist()}"
    )


def build_index(ipv4_csv_path: str = IPV4_CSV_PATH,
                 countries_csv_path: str = COUNTRIES_CSV_PATH) -> GeoIPIndex:
    """ipv4.csv, countries.csv를 불러와 조회 가능한 인덱스(GeoIPIndex)를 생성.
    무거운 작업이므로 앱 시작 시 한 번만 호출하고, 프론트엔드에서 캐싱해서 재사용할 것."""

    ipv4_df = pd.read_csv(ipv4_csv_path)

    ipv4_df["start_int"] = ipv4_df["start_ip"].apply(lambda x: int(ipaddress.IPv4Address(x)))
    ipv4_df["end_int"] = ipv4_df["end_ip"].apply(lambda x: int(ipaddress.IPv4Address(x)))
    ipv4_df = ipv4_df.sort_values("start_int").reset_index(drop=True)

    start_list = ipv4_df["start_int"].tolist()
    end_list = ipv4_df["end_int"].tolist()
    country_list = ipv4_df["country_code"].tolist()

    countries_df = pd.read_csv(countries_csv_path)
    countries_df.columns = countries_df.columns.str.strip().str.lower()

    iso_col = _find_column(countries_df, ["iso", "iso2", "iso_a2", "country_code", "code"])
    lat_col = _find_column(countries_df, ["latitude", "lat"])
    lon_col = _find_column(countries_df, ["longitude", "lon", "lng"])
    try:
        name_col = _find_column(countries_df, ["country", "country_name", "name"])
    except KeyError:
        name_col = None

    countries_df = countries_df.drop_duplicates(subset=iso_col, keep="first")

    return GeoIPIndex(
        start_list=start_list,
        end_list=end_list,
        country_list=country_list,
        countries_df=countries_df,
        iso_col=iso_col,
        lat_col=lat_col,
        lon_col=lon_col,
        name_col=name_col,
    )


def _classify_special_ip(ip_obj: ipaddress.IPv4Address) -> str | None:
    """사설망 / Class D / Class E 여부를 판별. 해당 없으면 None.
    주의: Python ipaddress 모듈에서 Class E(240.0.0.0/4)는 is_private도 True로
    같이 잡히므로, Class D/E를 먼저 검사해야 '사설망'으로 잘못 분류되지 않는다."""
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_reserved:
        return "reserved"
    if ip_obj.is_private:
        return "private"
    return None


def _find_country_code(index: GeoIPIndex, ip_int: int) -> str | None:
    """정렬된 대역에서 이진 탐색으로 국가코드(ISO) 조회. 못 찾으면 None."""
    idx = bisect.bisect_right(index.start_list, ip_int) - 1
    if idx < 0 or not (index.start_list[idx] <= ip_int <= index.end_list[idx]):
        return None
    return index.country_list[idx]


def lookup_ip(index: GeoIPIndex, ip: str) -> dict:
    """IP 하나를 조회.
    항상 dict를 반환하며(None을 반환하지 않음), status 필드로 결과 종류를 구분한다.

    반환 예:
        {'ip': '8.8.8.8', 'status': 'ok', 'country_code': 'US',
         'country_name': 'United States', 'latitude': .., 'longitude': ..}
        {'ip': '192.168.0.1', 'status': 'private', 'country_code': None,
         'country_name': None, 'latitude': None, 'longitude': None}
    """
    base = {"ip": ip, "country_code": None, "country_name": None,
            "latitude": None, "longitude": None}

    try:
        ip_obj = ipaddress.IPv4Address(ip)
    except ValueError:
        return {**base, "status": "invalid"}

    special = _classify_special_ip(ip_obj)
    if special is not None:
        return {**base, "status": special}

    country_code = _find_country_code(index, int(ip_obj))
    if country_code is None:
        return {**base, "status": "not_found"}

    matched = index.countries_df[index.countries_df[index.iso_col] == country_code]
    if matched.empty:
        return {**base, "status": "no_coords", "country_code": country_code}

    row = matched.iloc[0]
    return {
        "ip": ip,
        "status": OK_STATUS,
        "country_code": country_code,
        "country_name": row[index.name_col] if index.name_col else None,
        "latitude": row[index.lat_col],
        "longitude": row[index.lon_col],
    }


def lookup_ips(index: GeoIPIndex, ips: list[str]) -> pd.DataFrame:
    """여러 IP를 한 번에 조회해 DataFrame으로 반환.
    (ip, status, country_code, country_name, latitude, longitude) 컬럼을 가짐.
    -> 지도용 필터링(status == 'ok')과 보안 통계(status별 집계)에 모두 활용."""
    rows = [lookup_ip(index, ip) for ip in ips]
    return pd.DataFrame(rows)