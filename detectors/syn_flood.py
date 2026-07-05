def detect(packet, flow):

    print('syn_flood 모듈 실행중')
    print(packet.raw_packet)
    if flow.protocol != "TCP":
        return

    if flow.syn_count > 100 and flow.pps > 50:

        print(
            "[SYN Flood]",
            packet.src_ip
        )