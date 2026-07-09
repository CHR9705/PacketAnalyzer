from engine import PacketData, Flow
from detectors.amplification_common import AmplificationDetector


detector = AmplificationDetector(5)


def detect(packet: PacketData, flow: Flow):

    # print("[DNS Amplification Detector]")
    # print(f"  {packet.raw_packet}")
    if flow.protocol != "UDP":
        return (False, "")

    # DNS Response
    if packet.src_port != 53:
        return (False, "")

    result = detector.add_packet(packet)

    if (
        result.packet_count >= 80
        or result.total_bytes >= 2_000_000
        or result.unique_servers >= 20
    ):

        print("\n[DNS Amplification 의심됨]")

        return (True, "DNS Amplification")
    return (False, "")