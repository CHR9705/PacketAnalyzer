from engine import PacketData, Flow

def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return

    if flow.duration < 2:
        return

    port_count = len(flow.scanned_ports)

    if port_count < 20:
        return

    print(f"""
    [UDP Scan]
    공격 IP = {packet.src_ip}
    스캔한 포트 수 = {port_count}
    지속 시간 = {flow.duration:.2f}초
    """)


        # flow.manager에 넣을 코드
        # if packet.protocol == "UDP":
            # flow.scanned_ports.add(packet.dst_port)

        # flow에 넣을 코드    
        # scanned_ports: set = field(default_factory=set)