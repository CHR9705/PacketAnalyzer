from engine import PacketData, Flow
from datetime import datetime
from .Flood_conditions import flood_conditions

MY_IP = "192.168.11.129"  

def detect(packet:  PacketData, flow: Flow):
    """
    FIN Flood 공격을 받을 때 탐지
    """
    
    condition= flood_conditions(flow)
    if condition is None:
        return(False, "")
    
    packet_count = condition["packet_count"]

    inbound_fin = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="F")
        if p.dst_ip == MY_IP ] # MY_IP로 들어오는 것만 카운트
    outbound_rst = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="R")
        if p.src_ip == MY_IP] # 내가 보내는 RST

    fin_count = len(inbound_fin)
    rst_count = len(outbound_rst)

    if packet_count == 0:
        return (False, "")

    if fin_count == 0:
        return (False, "")
    
    fin_ratio = fin_count / packet_count
    rst_ratio = rst_count / fin_count
    
    if packet_count >= 100 and fin_ratio >= 0.5 and rst_ratio >= 0.4:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 fin 비율: {fin_ratio:.2f}")
        print ("FIN Flood 공격을 받고 있습니다.")
        return(True,"FIN Flood")
    return(False, "")
