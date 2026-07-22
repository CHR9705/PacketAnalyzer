from engine import PacketData, Flow
from datetime import datetime
from .Flood_conditions import flood_conditions

MY_IP = "192.168.11.129"  

def detect(packet: PacketData, flow: Flow):
    """
    SYN Flood 공격을 받을 때 탐지
    """

    condition = flood_conditions(flow)
    if condition is None:
        return (False, "")

    packet_count = condition["packet_count"]

    # 인바운드 패킷만 기준으로 flag별 카운트
    # (내가 보낸 RST 응답 등은 애초에 flow 구성 단계에서
    #  src_ip == MY_IP 인 패킷은 제외하는 게 이상적)
    inbound_syn = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="S")
        if p.dst_ip == MY_IP ] # MY_IP로 들어오는 것만 카운트
    outbound_rst = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="R")
        if p.src_ip == MY_IP] # 내가 보내는 RST
    outbound_fin = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="F")
        if p.src_ip == MY_IP] # 내가 보내는 FIN

    syn_count = len(inbound_syn)
    rst_count = len(outbound_rst)
    fin_count = len(outbound_fin)

    if packet_count == 0:
        return (False, "")

    if syn_count == 0:
        return (False, "")

    syn_ratio = syn_count / packet_count
    rst_ratio = rst_count / syn_count
    fin_ratio = fin_count / syn_count
    
    if packet_count >= 100 and syn_ratio >= 0.5 and rst_ratio >= 0.4 and fin_ratio <= 0.5:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 syn 비율: {syn_ratio:.2f} / rst 비율: {rst_ratio:.2f}")
        print("SYN Flood 공격을 받고 있습니다.")
        return (True, "SYN Flood")
    return (False, "")
