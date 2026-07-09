from engine import PacketData, Flow
from detectors.amplification_common import AmplificationDetector

detector = AmplificationDetector(5)


def detect(packet: PacketData, flow: Flow):

    if flow.protocol != "UDP":
        return (False, "")

    if packet.src_port != 123:
        return (False, "")

    result = detector.add_packet(packet)

    if (
        result.packet_count >= 80
        or result.total_bytes >= 2_000_000
    ):

        print("\n[NTP Amplification Suspected]")
        return (True, "NTP Amplification")
    
    return (False, "")