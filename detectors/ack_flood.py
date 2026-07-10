from engine import PacketData, Flow
from datetime import datetime
from .Flood_conditions import flood_conditions

def detect(packet:  PacketData, flow: Flow):
    """
    ACK Flood 공격을 받을 때 탐지
    """

    condition= flood_conditions (flow)

    if condition is None:
        return(False, "")
    
    packet_count = condition["packet_count"]
    
    ack_count = len(flow.get_recent_packets_by_flag(seconds=10, flag="A"))

    ack_ratio = ack_count / packet_count
    
    if packet_count >= 100 and ack_ratio >= 0.65:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 ack 비율: {ack_ratio:.2f}")
        print ("ACK Flood 공격을 받고 있습니다.")
        return(True,"ACK Flood")
    return(False, "")
