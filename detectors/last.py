from engine import PacketData, Flow

# SYN, ACK, FIN 탐지

def detect(packet: PacketData, flow: Flow):

    print('flood 모듈 실행중')
    print(packet.raw_packet)

    if flow.protocol != "TCP":
        return
    if flow.duration < 1:
        return
    if flow.pps < 1000:
        return
    if flow.packet_count == 0:
        return
    syn_ratio = flow.syn_count / flow.packet_count
    ack_ratio = flow.ack_count / flow.packet_count
    fin_ratio = flow.fin_count / flow.packet_count

    if flow.syn_count >= 500 and syn_ratio >= 0.8:
        print("SYN Flood")
        print(packet.timestamp, packet.src_ip)
    if flow.ack_count >= 500 and ack_ratio >= 0.8:
        print("ACK Flood")
        print(packet.timestamp, packet.src_ip)
    if flow.fin_count >= 500 and fin_ratio >= 0.8:
        print("FIN Flood")
        print(packet.timestamp, packet.src_ip)


