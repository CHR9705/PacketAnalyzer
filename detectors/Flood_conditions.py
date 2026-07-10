from engine import Flow

def flood_conditions(flow: Flow):
    """
    조건값
    """

    if flow.protocol != "TCP":
        return None
    
    recent_packets = flow.get_packets(seconds=10)
    packet_count = len(recent_packets)

    if packet_count == 0 :
        return None
    
    recent_duration = (recent_packets[-1].timestamp - recent_packets[0].timestamp)

    if recent_duration < 2:
        return None

    pps = packet_count / recent_duration

    if pps < 300:
        return None

    return {"packet_count": packet_count,"pps": pps,"duration": recent_duration}