from engine import PacketData, Flow
from datetime import datetime
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
    """
    SYN Flood 공격을 받을 때 탐지
    """

    if not hasattr(detect, "_my_ip"):
        detect._my_ip = get_local_ip()

    MY_IP = detect._my_ip

    condition = flood_conditions(flow)
    if condition is None:
        return (False, "")

    packet_count = condition["packet_count"]

    # 인바운드 패킷만 기준으로 flag별 카운트
    # (내가 보낸 RST 응답 등은 애초에 flow 구성 단계에서
    #  src_ip == MY_IP 인 패킷은 제외하는 게 이상적)
    inbound_syn = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="S")
        if p.dst_ip == MY_IP ] # MY_IP로 들어오는 것만 카운트
    
    inbound_ack = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="A")
        if p.dst_ip == MY_IP] # 내가 보내는 RST
    
    outbound_fin = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="F")
        if p.src_ip == MY_IP] # 내가 보내는 FIN

    syn_count = len(inbound_syn)
    ack_count = len(inbound_ack)
    fin_count = len(outbound_fin)

    

    if packet_count == 0:
        return (False, "")

    if syn_count == 0:
        return (False, "")

    syn_ratio = syn_count / packet_count
    ack_ratio = ack_count / syn_count
    fin_ratio = fin_count / syn_count

    # print(syn_ratio, ack_ratio ,fin_ratio)
    
    if packet_count >= 100 and syn_ratio >= 0.2 and ack_ratio < 1 and fin_ratio <= 0.5:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 syn 비율: {syn_ratio:.2f} / ack 비율: {ack_ratio:.2f}")
        print("SYN Flood 공격을 받고 있습니다.")
        return (True, "SYN Flood")
    return (False, "")
