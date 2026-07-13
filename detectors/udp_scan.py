from engine import PacketData, Flow

def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return(False, "")
    
    recent_packets = flow.get_packets(seconds=10)

    if len(recent_packets) == 0:
        return (False, "")
    
    ports = {pkt.dst_port for pkt in recent_packets}

    port_count = len(ports)
    packet_count = len(recent_packets)
    
    if packet_count >= 50 and port_count >= 20:
        print(f"""
        [UDP Scan]
        공격 IP = {packet.src_ip}
        스캔한 포트 수 = {port_count}
        지속 시간 = {flow.duration:.2f}초""")
        return(True, "UDP Scan")
    return(False,"")