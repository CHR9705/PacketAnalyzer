from engine import PacketData, Flow
from .Flood_conditions import flood_conditions
import socket


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

    # 최초 호출 시 한 번만 로컬 IP 확인 (캐싱)
    if not hasattr(detect, "_my_ip"):
        detect._my_ip = get_local_ip()

    my_ip = detect._my_ip

    # 내가 보낸 패킷은 탐지 대상에서 제외
    if my_ip and packet.src_ip == my_ip:
        return (False, "")
    if my_ip and packet.dst_ip != my_ip:
        return (False, "")
    condition = flood_conditions(flow)
    RST_THRESHOLD = 100
    if condition is None:
        return (False, "")

    flags = packet.tcp_flags or ""
    if "R" not in flags:
        return (False, "")

    if flow.rst_count >= RST_THRESHOLD:
        print("[RST Flood]", packet.src_ip)
        return (True, "RST Flood")

    return (False, "")