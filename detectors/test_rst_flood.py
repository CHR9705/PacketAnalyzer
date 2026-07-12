from engine import PacketData, Flow


def detect(packet: PacketData, flow: Flow):

    # print('rst_flood 테스트중')
    # 임계점 설정이라 변경가능.
    
    RST_THRESHOLD = 50

    flags = packet.tcp_flags or ""
    if "R" not in flags:
        return (False, "")

    if flow.rst_count >= RST_THRESHOLD:
        print(
            "[RST Flood]",
            packet.src_ip
        )
        return (True, "RST Flood")
    return (False, "")
    



