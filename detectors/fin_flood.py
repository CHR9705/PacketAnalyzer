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

def detect(packet:  PacketData, flow: Flow):
    """
    FIN Flood 공격을 받을 때 탐지
    """
    
    if not hasattr(detect, "_my_ip"):
        detect._my_ip = get_local_ip()

    MY_IP = detect._my_ip
    

    condition= flood_conditions(flow)
    if condition is None:
        return(False, "")
    
    packet_count = condition["packet_count"]

    inbound_fin = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="F")
        if p.dst_ip == MY_IP ] # MY_IP로 들어오는 것만 카운트
        
    outbound_fin = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="F")
        if p.src_ip == MY_IP ] # MY_IP로 들어오는 것만 카운트
     
    syn =  flow.get_recent_packets_by_flag(seconds=10, flag="S")
    outbound_rst = [p for p in flow.get_recent_packets_by_flag(seconds=10, flag="S")
        if p.src_ip == MY_IP] # 내가 보내는 RST

    fin_count = len(inbound_fin)
    out_fin_count = len(outbound_fin)
    rst_count = len(outbound_rst)
    syn_count = len(syn)

    if packet_count == 0:
        return (False, "")

    if fin_count == 0:
        return (False, "")
    
    fin_ratio = fin_count / packet_count
    rst_ratio = rst_count / fin_count
    syn_ratio = syn_count / fin_count
    out_fin_ratio = out_fin_count / fin_count
    
    # print(fin_ratio, rst_ratio, syn_ratio, out_fin_ratio)
    if packet_count >= 100 and fin_ratio >= 0.5 and syn_ratio < 0.2 and out_fin_ratio < 0.2:
        print(datetime.fromtimestamp(packet.timestamp), packet.src_ip)
        print(f"총 패킷 중 fin 비율: {fin_ratio:.2f}")
        print ("FIN Flood 공격을 받고 있습니다.")
        return(True,"FIN Flood")
    return(False, "")