from engine import PacketData, Flow

def detect(packet: PacketData, flow: Flow):

    # print('udp_flood 모듈 실행중')
    if flow.protocol != "UDP":
        return

    if flow.pps > 100 and flow.bps > 50:

        print(
            "[UDP Flood]",
            packet.src_ip
        )
        return (True, "UDP Flood")
    
    return (False, "")