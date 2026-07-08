"""
SYN Scan / FIN Scan 탐지 모듈

전제:
- 프레임워크가 패킷을 하나씩 파싱해서 packet 객체로 넘겨준다.
  (packet.timestamp, packet.protocol, packet.src_ip, packet.dst_port,
   packet.tcp_flags 등을 이미 속성으로 가지고 있음)
- 이 모듈은 packet, flow 객체를 받아서 detect(packet, flow) 형태로 호출하면 됨.

탐지 대상:
- SYN Scan : tcp_flags가 "S"(SYN만 켜짐)인 패킷
- FIN Scan : tcp_flags가 "F"(FIN만 켜짐)인 패킷
- SYN/FIN 분산 스캔(Distributed Scan) : 위 두 종류를, 한 목적지 IP를
  기준으로 봤을 때 여러 출발지 IP가 몰려서 접근하는 경우까지 함께 탐지

판단 기준:
- (포트 스캔) 같은 출발지 IP가 TIME_WINDOW(초) 안에
  PORT_THRESHOLD개 이상의 "서로 다른 포트"에 접근하면 스캔으로 판단.
  포트별로 몇 번 접근했는지도 함께 집계.
- (분산 스캔) 같은 목적지 IP에 DIST_TIME_WINDOW(초) 안에
  DIST_IP_THRESHOLD개 이상의 "서로 다른 출발지 IP"가 접근하면 분산 스캔으로 판단.
  출발지 IP별로 몇 번 접근했는지도 함께 집계.

---------------------------------------------------------------------------
[설계 노트] 왜 flow 객체가 아니라 packet 객체를 기준으로 집계하는가?
---------------------------------------------------------------------------
프레임워크가 제공하는 flow 객체는 "IP주소 + Port번호 쌍이 동일한 패킷들의 묶음"을
기준으로 만들어진다. 즉, 두 endpoint(ip, port)가 완전히 같아야만 같은 flow로
인식된다.

그런데 포트 스캔 공격은 정의상 "같은 출발지 IP가 목적지의 여러 포트를
돌아가며 건드리는" 행위다. 목적지 포트가 바뀌는 순간 endpoint 조합이
달라지므로, flow 입장에서는 매번 "새로운 flow"가 시작된 것으로 처리된다.

예시) 공격자 2.2.2.2가 192.168.0.1의 22, 80, 443번 포트를 순서대로 스캔하면:

    flow_1: 2.2.2.2:5000 <-> 192.168.0.1:22   -> syn_count = 1
    flow_2: 2.2.2.2:5001 <-> 192.168.0.1:80   -> syn_count = 1
    flow_3: 2.2.2.2:5002 <-> 192.168.0.1:443  -> syn_count = 1

각 flow 는 SYN을 딱 1번만 가지고 있는, 지극히 평범한 연결 시도처럼 보인다.
flow.syn_count 같은 값을 아무리 들여다봐도 "이 IP가 여러 포트에 걸쳐
넓게 접근하고 있다"는 패턴 자체가 애초에 flow 하나의 시야 안에는
존재하지 않는다. flow는 "이 대화 하나가 얼마나 활발한가"를 보는 단위이지,
"이 IP가 몇 개의 서로 다른 목적지 포트에 접근했는가"를 보는 단위가 아니기
때문이다. 즉 flow 기반 집계는 구조적으로 포트 스캔을 탐지할 수 없다.

반면 packet 객체는 flow 경계와 무관하게 패킷이 들어오는 즉시 개별적으로
넘어온다. 그래서 이 모듈은 flow를 거치지 않고, packet이 들어올 때마다
"출발지 IP" 하나를 기준으로 직접 누적한다. dst_port가 바뀌어도
같은 src_ip 아래 계속 같은 딕셔너리에 쌓이기 때문에, 목적지 포트가 22 -> 80
-> 443 으로 바뀌며 여러 flow가 새로 생성되더라도 그 사실과 무관하게
"이 IP가 지금까지 총 몇 개의 서로 다른 포트를 건드렸는지"를 끊김 없이
추적할 수 있다.

정리하면:

    | 구분           | flow 기반                  | packet 기반 (본 모듈)        |
    |----------------|-----------------------------|-------------------------------|
    | 집계 단위      | IP + Port 쌍 (flow 하나)     | 출발지 IP 하나                |
    | 목적지 포트 변경 시 | 새로운 flow로 분리 -> 못 봄 | 같은 IP 아래 계속 합산 -> 잡힘 |
    | 포트 스캔 탐지 가능 여부 | 불가능 (설계상 한계)     | 가능                           |
---------------------------------------------------------------------------

[구현 노트] 슬라이딩 윈도우를 "IP 단위"가 아닌 "포트 단위"로 관리하는 이유
---------------------------------------------------------------------------
IP를 처음 관측한 시각(first_seen) 하나만 기준으로 삼으면 문제가 생긴다.
예를 들어 어떤 IP가 t=0초에 22번 포트를, t=4초에 80번 포트를 건드렸다면,
t=6초 시점에 "IP를 처음 본 지 5초가 넘었다"는 이유로 22번 포트뿐 아니라
방금(2초 전) 찍힌 80번 포트 기록까지 통째로 지워지는 오류가 생긴다.

그래서 이 모듈은 IP 전체가 아니라 "포트 하나하나"마다 last_seen(마지막으로
그 포트가 찍힌 시각)을 따로 기록한다. 포트별로 "마지막으로 본 지 5초가
지났는지"를 개별 판단하기 때문에, 오래된 포트만 정확히 제거되고 최근에
찍힌 포트는 그대로 살아있는다. 이게 진짜 의미의 슬라이딩 윈도우(sliding
window)다.
---------------------------------------------------------------------------

[설계 노트] 분산 스캔(Distributed Scan)은 왜 별도의 축이 필요한가?
---------------------------------------------------------------------------
위쪽 로직(scan_log)은 전부 "출발지 IP 하나" 기준으로 포트를 모은다.
그런데 봇넷처럼 여러 IP가 역할을 나눠서, 한 IP당 포트를 1~2개씩만
찔러보고 빠지는 방식으로 공격하면 어떻게 될까?

예시) 공격자가 IP 100개를 동원해서 우리 서버 192.168.0.1의
포트 1~100번을 한 IP당 1개씩 나눠서 찌른다면:

    1.1.1.1 -> 192.168.0.1:1    (SYN 1개)
    1.1.1.2 -> 192.168.0.1:2    (SYN 1개)
    1.1.1.3 -> 192.168.0.1:3    (SYN 1개)
    ...     (총 100개 IP, 각자 딱 1개 포트만)

scan_log 기준으로 보면 각 IP는 "포트 1개짜리, 지극히 평범한 연결
시도"로만 보인다. PORT_THRESHOLD(10개)에 단 하나도 도달하지 못하므로
지금까지의 로직으로는 전혀 잡히지 않는다. 이게 "IP 기준 집계"의
구조적인 사각지대다.

그래서 분산 스캔은 관점을 뒤집어야 한다: "공격자가 누구냐"가 아니라
"우리가 지키는 목적지(dst_ip)가 지금 얼마나 많은, 서로 다른 출발지
IP로부터 몰아치기를 당하고 있느냐"를 본다. 즉 집계 축을 src_ip가
아니라 dst_ip로 바꾸고, 그 밑에서 "서로 다른 src_ip의 개수"를 센다.

    dist_scan_log[scan_type][dst_ip][src_ip] = {count, last_seen}

구조 자체는 scan_log와 완전히 동일한 3단계 defaultdict이고, 판단
로직(만료 처리, 임계치 비교)도 동일한 패턴을 그대로 재사용한다.
다른 점은 딱 하나, "IP 하나 아래 포트를 모으느냐" 대신
"목적지 하나 아래 출발지 IP를 모으느냐"라는 관점 뿐이다.

정리하면 이 모듈은 이제 두 가지 시야를 동시에 가진다:

    | 구분       | scan_log (기존)              | dist_scan_log (신규)           |
    |------------|-------------------------------|----------------------------------|
    | 집계 기준  | 출발지 IP 하나                 | 목적지 IP 하나                    |
    | 세는 대상  | 그 IP가 건드린 서로 다른 포트   | 그 목적지에 접근한 서로 다른 IP    |
    | 잡는 패턴  | 한 명이 여러 곳을 찌름 (SYN/FIN Scan) | 여러 명이 한 곳을 찌름 (분산 스캔) |
---------------------------------------------------------------------------
"""

from collections import defaultdict

from engine import PacketData, Flow

# ----------------------------
# 설정값
# ----------------------------
TIME_WINDOW = 5      # 이 시간(초) 동안 접근이 없으면 "오래된 포트"로 보고 지움
PORT_THRESHOLD = 10  # 서로 다른 포트가 이 개수 이상이면 스캔으로 판단

# 분산 스캔용 설정값 (기존 값과 별도로 관리 -> 나중에 감도를 독립적으로 조절 가능)
DIST_TIME_WINDOW = 5      # 이 시간(초) 동안 접근이 없으면 "오래된 출발지 IP"로 보고 지움
DIST_IP_THRESHOLD = 20    # 한 목적지에 서로 다른 출발지 IP가 이 개수 이상 몰리면 분산 스캔으로 판단

SCAN_TYPES = ("SYN", "FIN")

# ----------------------------
# scan_log 구조
# ----------------------------
# scan_log["SYN"]["1.2.3.4"][80] = {"count": 3, "last_seen": 12345.67}
#   -> SYN 기준으로, 1.2.3.4가 80번 포트에 3번 접근했고
#      가장 최근 접근 시각은 12345.67 이었다는 뜻.
#
# 3단계 defaultdict 구조:
#  1) 스캔종류(SYN/FIN) -> 2) 출발지 IP -> 3) 목적지 포트 -> {count, last_seen}
# 존재하지 않는 key로 접근해도 자동으로 기본값이 채워지므로,
# "이 IP 처음 보나?", "이 포트 처음 보나?" 같은 체크를 따로 할 필요가 없다.
scan_log = {
    t: defaultdict(lambda: defaultdict(lambda: {
        "count": 0,
        "last_seen": 0
    }))
    for t in SCAN_TYPES
}

# 이미 경고를 출력한 IP (스캔 종류별로 따로 관리해서 SYN/FIN 경고가 서로 섞이지 않게 함)
alerted_ips = {
    t: set()
    for t in SCAN_TYPES
}

# 탐지된 스캔 이력. SYN과 FIN을 처음부터 별도의 리스트에 담아 절대 합쳐지지 않도록 한다.
# 구조: scan_history["SYN"] = [ {기록1}, {기록2}, ... ]
scan_history = {
    t: []
    for t in SCAN_TYPES
}

# ----------------------------
# dist_scan_log 구조 (분산 스캔용)
# ----------------------------
# dist_scan_log["SYN"]["192.168.0.1"]["1.1.1.5"] = {"count": 2, "last_seen": 12345.67}
#   -> SYN 기준으로, 목적지 192.168.0.1에 1.1.1.5라는 출발지 IP가 2번 접근했고
#      가장 최근 접근 시각은 12345.67 이었다는 뜻.
#
# scan_log와 똑같은 3단계 defaultdict 구조이되, 기준이 뒤집혀 있다:
#  1) 스캔종류(SYN/FIN) -> 2) 목적지 IP -> 3) 출발지 IP -> {count, last_seen}
dist_scan_log = {
    t: defaultdict(lambda: defaultdict(lambda: {
        "count": 0,
        "last_seen": 0
    }))
    for t in SCAN_TYPES
}

# 분산 스캔으로 이미 경고를 출력한 "목적지 IP" (scan_log 쪽과는 완전히 별개로 관리)
dist_alerted_ips = {
    t: set()
    for t in SCAN_TYPES
}

# 탐지된 분산 스캔 이력. 기존 scan_history와 섞이지 않도록 이름부터 분리.
dist_scan_history = {
    t: []
    for t in SCAN_TYPES
}


def _reset_old(log, alerted, scan_type, window, now):
    """
    log[scan_type][바깥key][안쪽key] = {count, last_seen} 형태의 3단계
    구조라면 어디에나 쓸 수 있는 공용 만료 처리 함수.

    - 포트 스캔 쪽에 쓰면: 바깥key=출발지 IP, 안쪽key=포트
    - 분산 스캔 쪽에 쓰면: 바깥key=목적지 IP, 안쪽key=출발지 IP

    안쪽key 중 window(초)보다 오래된 것만 지우고, 바깥key 밑에
    남은 안쪽key가 하나도 없으면 바깥key 자체와 alerted 기록도 지운다.
    """
    expired_outer_keys = []

    for outer_key, inner_map in log[scan_type].items():
        expired_inner_keys = [
            k for k, info in inner_map.items()
            if now - info["last_seen"] > window
        ]
        for k in expired_inner_keys:
            del inner_map[k]

        if len(inner_map) == 0:
            expired_outer_keys.append(outer_key)

    for outer_key in expired_outer_keys:
        log[scan_type].pop(outer_key, None)
        alerted[scan_type].discard(outer_key)


def _check_threshold(log, alerted, history, scan_type, outer_key, threshold, now, title, outer_label, inner_label, key_name):
    """
    _reset_old와 짝을 이루는 공용 판정 함수. 안쪽key 개수가 threshold를
    넘었는지 확인하고, 넘었으면 출력 + history 기록을 남긴다.

    title/outer_label/inner_label은 출력 문구만 바꿔주는 값이라서,
    "SYN Scan / Source IP / Port"처럼 넘기면 포트 스캔 출력이,
    "SYN Distributed Scan / Target IP / Source"처럼 넘기면 분산 스캔
    출력이 된다. 로직은 완전히 동일하다.

    key_name은 history에 저장될 때 outer_key를 어떤 이름의 필드로 남길지
    결정한다. 포트 스캔 쪽에서는 "src_ip", 분산 스캔 쪽에서는 "dst_ip"를
    넘겨서, 나중에 기록을 분석할 때 record["src_ip"]처럼 의미가 분명한
    이름으로 바로 꺼내볼 수 있게 한다 (모호한 "key"라는 이름 대신).
    """
    inner_map = log[scan_type][outer_key]
    unique_count = len(inner_map)

    if unique_count < threshold or outer_key in alerted[scan_type]:
        return

    print(f"\n========== {scan_type} {title} Detected ==========")
    print(f"{outer_label} : {outer_key}")
    print(f"Unique {inner_label}s : {unique_count}")
    print("-" * 47)

    counts = {}
    for inner_key in sorted(inner_map):
        c = inner_map[inner_key]["count"]
        counts[inner_key] = c
        print(f"{inner_label} {inner_key!s:<15} : {c}회")

    print("=" * 47 + "\n")

    history[scan_type].append({
        key_name: outer_key,
        "detected_at": now,
        "unique_count": unique_count,
        "counts": counts,
    })

    alerted[scan_type].add(outer_key)


def detect(packet: PacketData, flow: Flow):
    """
    엔진이 패킷 하나마다 호출해주는 진입점 함수.

    flow는 엔진 인터페이스(detect(packet, flow) 규격)를 맞추기 위해
    전달받지만, 위쪽 [설계 노트]에서 설명했듯 포트 스캔은 flow 단위
    (IP+Port 쌍)로는 원천적으로 탐지할 수 없으므로 실제 로직에서는
    사용하지 않고 packet만 사용한다.
    """
    # TCP가 아니면 SYN/FIN 플래그 자체가 존재하지 않으므로 바로 종료
    if packet.protocol != "TCP":
        return

    flags = packet.tcp_flags

    # SYN만 켜진 패킷 -> SYN 스캔 후보, FIN만 켜진 패킷 -> FIN 스캔 후보
    #
    # 참고: flags == "S"는 문자열이 정확히 일치할 때만 True이므로
    # "SA"(SYN+ACK) 같은 조합은 이 시점에 이미 걸러진다. len(flags) == 1은
    # 논리적으로는 중복 조건이지만, 나중에 누군가 이 비교를 "S" in flags 같은
    # 느슨한 방식으로 바꾸는 실수를 하더라도 최소한의 안전장치가 되도록
    # 명시적으로 남겨둔다.
    if flags == "S" and len(flags) == 1:
        scan_type = "SYN"
    elif flags == "F" and len(flags) == 1:
        scan_type = "FIN"
    else:
        return  # 그 외 플래그(A, SA, R 등)는 이 모듈에서 다루지 않음

    src_ip = packet.src_ip
    dst_ip = packet.dst_ip
    dst_port = packet.dst_port
    now = packet.timestamp

    # --- (A) 포트 스캔 축: 출발지 IP 하나 -> 여러 포트 ---
    _reset_old(scan_log, alerted_ips, scan_type, TIME_WINDOW, now)

    port_info = scan_log[scan_type][src_ip][dst_port]
    port_info["count"] += 1
    port_info["last_seen"] = now

    _check_threshold(
        scan_log, alerted_ips, scan_history, scan_type,
        outer_key=src_ip, threshold=PORT_THRESHOLD, now=now,
        title="Scan", outer_label="Source IP", inner_label="Port",
        key_name="src_ip"
    )

    # --- (B) 분산 스캔 축: 목적지 IP 하나 -> 여러 출발지 IP ---
    _reset_old(dist_scan_log, dist_alerted_ips, scan_type, DIST_TIME_WINDOW, now)

    dist_info = dist_scan_log[scan_type][dst_ip][src_ip]
    dist_info["count"] += 1
    dist_info["last_seen"] = now

    _check_threshold(
        dist_scan_log, dist_alerted_ips, dist_scan_history, scan_type,
        outer_key=dst_ip, threshold=DIST_IP_THRESHOLD, now=now,
        title="Distributed Scan", outer_label="Target IP", inner_label="Source",
        key_name="dst_ip"
    )


def _get_history(history, scan_type):
    """
    scan_history/dist_scan_history 둘 다에 쓸 수 있는 공용 조회 함수.
    scan_type이 "SYN"/"FIN"이 아니면 예외를 발생시켜서, 잘못된 값으로
    두 이력을 혼동해서 요청하는 것 자체를 막는다.
    """
    if scan_type not in SCAN_TYPES:
        raise ValueError(f"scan_type은 {SCAN_TYPES} 중 하나여야 합니다.")
    return history[scan_type]


def get_scan_history(scan_type):
    """포트 스캔(SYN/FIN) 이력만 조회."""
    return _get_history(scan_history, scan_type)


def get_dist_scan_history(scan_type):
    """분산 스캔(SYN/FIN) 이력만 조회."""
    return _get_history(dist_scan_history, scan_type)