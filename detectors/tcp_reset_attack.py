#  RST 개수만으로 공격을 판단하지 않았습니다. 
#  정상적인 TCP 통신에서도 RST가 발생할 수 있기 때문입니다. 
#  따라서 TCP 여부, 전체 패킷 대비 RST 비율(RST Ratio), 초당 패킷 수(PPS),   
#  그리고 정상적인 TCP 연결(SYN)이 있었는지를 함께 확인하여 TCP Reset Attack을 탐지하도록 구현했습니다.


from engine import PacketData, Flow
from datetime import datetime
from collections import defaultdict
import time


# ============================================================
# TCP RESET ATTACK 탐지 설정값
# ============================================================

MIN_PACKET_COUNT = 20       # 최소 패킷 수
MIN_RST_COUNT = 10          # 최소 RST 패킷 수
MIN_PPS = 50                # 최소 초당 패킷 수
MIN_RST_RATIO = 0.60        # 전체 패킷 중 RST 비율
MAX_FLOW_DURATION = 10.0    # 짧은 시간 안에 발생한 트래픽만 집중 분석

RST_SYN_RATIO = 3.0         # RST가 SYN보다 3배 이상이면 의심
RST_ACK_RATIO = 1.5         # RST가 ACK보다 1.5배 이상이면 의심
RST_FIN_RATIO = 3.0         # RST가 FIN보다 3배 이상이면 의심

DUPLICATE_SEQ_THRESHOLD = 5  # 동일 Sequence Number 반복 기준
ALERT_COOLDOWN = 10          # 동일 Flow 알림 재발생 제한 시간(초)


# Flow 객체를 직접 수정하지 못하는 경우를 대비한 외부 상태 저장소
flow_alert_history = {}
sequence_history = defaultdict(lambda: defaultdict(int))


def get_flow_key(packet: PacketData, flow: Flow):
    """
    동일한 TCP 흐름을 구분하기 위한 키 생성.

    PacketData에 src_port, dst_port가 없다면 0을 사용합니다.
    """

    src_port = getattr(packet, "src_port", 0)
    dst_port = getattr(packet, "dst_port", 0)

    return (
        packet.src_ip,
        src_port,
        packet.dst_ip,
        dst_port,
        flow.protocol,
    )


def get_flow_duration(flow: Flow):
    """
    Flow 객체 구조가 달라도 지속 시간을 계산할 수 있도록 처리합니다.
    """

    # engine에서 duration을 직접 계산하는 경우
    duration = getattr(flow, "duration", None)

    if duration is not None:
        return max(float(duration), 0.000001)

    # start_time, last_seen을 저장하는 경우
    start_time = getattr(flow, "start_time", None)
    last_seen = getattr(flow, "last_seen", None)

    if start_time is not None and last_seen is not None:
        return max(float(last_seen - start_time), 0.000001)

    # first_seen, last_seen 구조인 경우
    first_seen = getattr(flow, "first_seen", None)

    if first_seen is not None and last_seen is not None:
        return max(float(last_seen - first_seen), 0.000001)

    return 0.0


def get_tcp_sequence(packet: PacketData):
    """
    PacketData에서 TCP Sequence Number를 가져옵니다.
    필드가 존재하지 않으면 None을 반환합니다.
    """

    for field_name in ("seq", "tcp_seq", "sequence_number"):
        value = getattr(packet, field_name, None)

        if value is not None:
            return value

    return None


def is_rst_packet(packet: PacketData):
    """
    현재 패킷이 RST 패킷인지 확인합니다.
    PacketData 구조에 따라 여러 필드명을 지원합니다.
    """

    rst_flag = getattr(packet, "rst", None)

    if rst_flag is not None:
        return bool(rst_flag)

    flags = getattr(packet, "tcp_flags", None)

    if flags is None:
        flags = getattr(packet, "flags", None)

    if flags is None:
        return False

    # 문자열 형식: "R", "RA", "RST"
    if isinstance(flags, str):
        return "R" in flags.upper()

    # 정수형 TCP Flags에서 RST 비트는 0x04
    if isinstance(flags, int):
        return bool(flags & 0x04)

    return False


def check_duplicate_sequence(packet: PacketData, flow_key):
    """
    동일 Flow에서 같은 TCP Sequence Number가 반복되는지 확인합니다.
    """

    if not is_rst_packet(packet):
        return 0

    sequence_number = get_tcp_sequence(packet)

    if sequence_number is None:
        return 0

    sequence_history[flow_key][sequence_number] += 1

    return sequence_history[flow_key][sequence_number]


def alert_allowed(flow_key):
    """
    동일 Flow에서 알림이 지나치게 반복되지 않도록 제한합니다.
    """

    current_time = time.time()
    last_alert_time = flow_alert_history.get(flow_key, 0)

    if current_time - last_alert_time < ALERT_COOLDOWN:
        return False

    flow_alert_history[flow_key] = current_time
    return True


def calculate_threat_level(score: int):
    """
    탐지 점수에 따라 위협 수준을 결정합니다.
    """

    if score >= 9:
        return "CRITICAL"

    if score >= 7:
        return "HIGH"

    if score >= 5:
        return "MEDIUM"

    return "LOW"


def detect(packet: PacketData, flow: Flow):

    # ========================================================
    # 1. TCP 트래픽만 검사
    # ========================================================

    if flow.protocol != "TCP":
        return

    # ========================================================
    # 2. 최소 패킷 수 확인
    # ========================================================

    packet_count = getattr(flow, "packet_count", 0)

    if packet_count < MIN_PACKET_COUNT:
        return

    # ========================================================
    # 3. Flow 통계값 안전하게 가져오기
    # ========================================================

    rst_count = getattr(flow, "rst_count", 0)
    syn_count = getattr(flow, "syn_count", 0)
    ack_count = getattr(flow, "ack_count", 0)
    fin_count = getattr(flow, "fin_count", 0)
    pps = getattr(flow, "pps", 0.0)

    flow_duration = get_flow_duration(flow)

    # 최소 RST 패킷 수보다 적으면 공격으로 판단하지 않음
    if rst_count < MIN_RST_COUNT:
        return

    # ========================================================
    # 4. 비율 계산
    # ========================================================

    rst_ratio = rst_count / max(packet_count, 1)

    rst_syn_ratio = rst_count / max(syn_count, 1)
    rst_ack_ratio = rst_count / max(ack_count, 1)
    rst_fin_ratio = rst_count / max(fin_count, 1)

    # ========================================================
    # 5. 동일 Sequence Number 반복 확인
    # ========================================================

    flow_key = get_flow_key(packet, flow)

    duplicate_seq_count = check_duplicate_sequence(
        packet,
        flow_key,
    )

    # ========================================================
    # 6. 점수 기반 이상 행위 분석
    # ========================================================

    score = 0
    reasons = []

    # RST 비율
    if rst_ratio >= MIN_RST_RATIO:
        score += 3
        reasons.append(
            f"높은 RST 비율({rst_ratio:.2%})"
        )

    # PPS
    if pps >= MIN_PPS:
        score += 2
        reasons.append(
            f"높은 패킷 전송률({pps:.2f} PPS)"
        )

    # RST 절대 개수
    if rst_count >= 30:
        score += 2
        reasons.append(
            f"다수의 RST 패킷({rst_count}개)"
        )

    elif rst_count >= MIN_RST_COUNT:
        score += 1
        reasons.append(
            f"RST 패킷 증가({rst_count}개)"
        )

    # 짧은 시간 내 집중 발생
    if 0 < flow_duration <= MAX_FLOW_DURATION:
        score += 1
        reasons.append(
            f"짧은 Flow 지속 시간({flow_duration:.2f}초)"
        )

    # SYN 대비 과도한 RST
    if syn_count > 0 and rst_syn_ratio >= RST_SYN_RATIO:
        score += 2
        reasons.append(
            f"SYN 대비 과도한 RST({rst_syn_ratio:.2f}배)"
        )

    # ACK보다 RST가 과도하게 많음
    if ack_count > 0 and rst_ack_ratio >= RST_ACK_RATIO:
        score += 1
        reasons.append(
            f"ACK 대비 과도한 RST({rst_ack_ratio:.2f}배)"
        )

    # ACK가 거의 없는 상태에서 RST가 다수 발생
    if ack_count == 0 and rst_count >= MIN_RST_COUNT:
        score += 2
        reasons.append(
            "ACK 없이 RST 패킷 다수 발생"
        )

    # 정상 종료 FIN보다 RST가 과도하게 많음
    if fin_count > 0 and rst_fin_ratio >= RST_FIN_RATIO:
        score += 1
        reasons.append(
            f"FIN 대비 과도한 RST({rst_fin_ratio:.2f}배)"
        )

    # FIN이 전혀 없는데 RST가 다수 발생
    if fin_count == 0 and rst_count >= MIN_RST_COUNT:
        score += 1
        reasons.append(
            "정상 종료 FIN 없이 RST 발생"
        )

    # 동일 TCP Sequence Number 반복
    if duplicate_seq_count >= DUPLICATE_SEQ_THRESHOLD:
        score += 2
        reasons.append(
            f"동일 TCP Sequence Number 반복"
            f"({duplicate_seq_count}회)"
        )

    # ========================================================
    # 7. 핵심 탐지 조건
    # ========================================================

    core_condition = (
        rst_count >= MIN_RST_COUNT
        and rst_ratio >= MIN_RST_RATIO
        and pps >= MIN_PPS
    )

    # 핵심 조건을 만족하지 않거나 점수가 낮으면 종료
    if not core_condition:
        return

    if score < 5:
        return

    # ========================================================
    # 8. 중복 알림 방지
    # ========================================================

    if not alert_allowed(flow_key):
        return

    # ========================================================
    # 9. 위협 수준 결정
    # ========================================================

    threat_level = calculate_threat_level(score)

    src_port = getattr(packet, "src_port", "Unknown")
    dst_port = getattr(packet, "dst_port", "Unknown")

    sequence_number = get_tcp_sequence(packet)

    # ========================================================
    # 10. 탐지 로그 출력
    # ========================================================

    print("\n" + "=" * 70)
    print("🚨 TCP RESET ATTACK DETECTED 🚨")
    print("=" * 70)

    print(
        f"Time          : "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    print(f"Source        : {packet.src_ip}:{src_port}")
    print(f"Destination   : {packet.dst_ip}:{dst_port}")
    print(f"Protocol      : {flow.protocol}")

    print("-" * 70)

    print(f"Packets       : {packet_count}")
    print(f"SYN Count     : {syn_count}")
    print(f"ACK Count     : {ack_count}")
    print(f"FIN Count     : {fin_count}")
    print(f"RST Count     : {rst_count}")

    print("-" * 70)

    print(f"RST Ratio     : {rst_ratio:.2%}")
    print(f"RST/SYN Ratio : {rst_syn_ratio:.2f}")
    print(f"RST/ACK Ratio : {rst_ack_ratio:.2f}")
    print(f"RST/FIN Ratio : {rst_fin_ratio:.2f}")
    print(f"PPS           : {pps:.2f}")
    print(f"Flow Duration : {flow_duration:.2f} sec")

    if sequence_number is not None:
        print(f"TCP Sequence  : {sequence_number}")
        print(f"SEQ Repeated  : {duplicate_seq_count}")

    print("-" * 70)

    print(f"Detection Score : {score}")
    print(f"Threat Level    : {threat_level}")
    print("Status          : TCP Reset Attack Suspected")

    print("-" * 70)

    print("Detection Reasons:")

    for index, reason in enumerate(reasons, start=1):
        print(f"  {index}. {reason}")

    print("=" * 70)


# sudo hping3 -R -p <타깃_포트> <타깃_IP> --fast --count 1000
# sudo hping3 -R -p 443 192.168.72.129 --fast --count 1000