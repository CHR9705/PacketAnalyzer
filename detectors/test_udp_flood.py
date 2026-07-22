from engine import PacketData, Flow
import socket

# threshold는 일반 사용자 1명기준 (웹사용)
PPS_THRESHOLD = 300
BPS_THRESHOLD = 50000
SMALL_PACKET_SIZE = 100  # payload 기준 소형 패킷 임계치 (byte)


def get_local_ip():
    """실제 사용 중인 로컬 IP 확인 (외부로 나가는 라우트 기준)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # 실제 전송 없음, 라우팅 조회용
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def detect(packet: PacketData, flow: Flow):

    if not hasattr(detect, "_my_ip"):
        detect._my_ip = get_local_ip()
    my_ip = detect._my_ip
    # 내가 보낸 패킷은 탐지 대상에서 제외
    if my_ip and packet.src_ip == my_ip:
        return (False, "")
    if my_ip and packet.dst_ip != my_ip:
            return (False, "")

    if flow.protocol != "UDP":
        return (False, "")

    payload_size = packet.payload_size if packet.payload_size is not None else 0

    is_high_rate = flow.pps > PPS_THRESHOLD and flow.bps > BPS_THRESHOLD
    is_small_packet_flood = (
        flow.avg_packet_size < SMALL_PACKET_SIZE
        and payload_size < SMALL_PACKET_SIZE
    )

    if is_high_rate and is_small_packet_flood:
        print(
            "[UDP Flood]",
            packet.src_ip,
            f"pps={flow.pps}, bps={flow.bps}, "
            f"avg_size={flow.avg_packet_size:.1f}B, payload_len={payload_size}B",
        )
        return (True, "UDP Flood")

    return (False, "")