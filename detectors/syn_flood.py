from engine import PacketData, Flow
from datetime import datetime
from .Flood_conditions import flood_conditions

def detect(packet:  PacketData, flow: Flow):
    """
    SYN Flood 공격을 받을 때 탐지
    """
    
    # print(flow.packet_count)
    
    condition= flood_conditions(flow)
    
    if condition is None:
        return(False,"")

    packet_count = condition["packet_count"]

    syn_count = len(flow.get_recent_packets_by_flag(seconds=10, flag="S"))

    syn_ratio = syn_count / packet_count
    
    if packet_count >= 100 and syn_ratio >= 0.65:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 syn 비율: {syn_ratio:.2f}")
        print("SYN Flood 공격을 받고 있습니다.")
        return(True,"SYN Flood")
    return (False,"")
