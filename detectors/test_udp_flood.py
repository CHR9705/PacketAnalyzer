from engine import PacketData, Flow

#threshold는 일반 사용자 1명기준 (웹사용)
PPS_THRESHOLD = 300
BPS_THRESHOLD = 50000       
SMALL_PACKET_SIZE = 100


def detect(packet: PacketData, flow: Flow):
    if flow.protocol != "UDP":
        return

    packet.payload_size if packet.payload_size else 0

    is_high_rate = flow.pps > PPS_THRESHOLD and flow.bps > BPS_THRESHOLD
    is_small_packet_flood = flow.avg_packet_size < SMALL_PACKET_SIZE

    if is_high_rate and is_small_packet_flood:
        print(
            "[UDP Flood]",
            packet.src_ip,
            f"pps={flow.pps}, bps={flow.bps}, "
            f"avg_size={flow.avg_packet_size:.1f}B, payload_len={packet.payload_size}B",
        )
        return (True, "UDP Flood")

    return (False, "")