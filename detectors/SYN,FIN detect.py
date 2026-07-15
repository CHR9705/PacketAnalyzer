from engine import PacketData, Flow

PORT_THRESHOLD = 10
PPS_THRESHOLD = 20


def detect(packet: PacketData, flow: Flow):

    # TCP가 아니면 검사하지 않음
    if flow.protocol != "TCP":
        return (False, "")

    # SYN 또는 FIN 패킷만 검사
    if packet.tcp_flags not in ("S", "F"):
        return (False, "")

    # 최근 50개 패킷 기준으로 해당 출발지 IP가 접근한 목적지 포트
    unique_ports = flow.get_dst_unique_ports(10, packet.src_ip)

    # 패킷 종류에 따라 카운트 선택
    if packet.tcp_flags == "S":
        scan_type = "SYN"
        scan_count = flow.syn_count
    else:
        scan_type = "FIN"
        scan_count = flow.fin_count

    # Scan 탐지
    if (
        len(unique_ports) >= PORT_THRESHOLD
        and scan_count >= PORT_THRESHOLD
        and flow.pps >= PPS_THRESHOLD
    ):

        print(
            f"[{scan_type} Scan Detected]",
            f"src={packet.src_ip}",
            f"ports={sorted(unique_ports)}",
            f"{scan_type.lower()}={scan_count}",
            f"pps={flow.pps:.2f}"
        )
        return (True, f"{scan_type} Scan")
    return (False, "")