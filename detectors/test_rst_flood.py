from engine import PacketData, Flow
from .Flood_conditions import flood_conditions


def detect(packet: PacketData, flow: Flow):

    # print('rst_flood 테스트중')
    # 임계점 설정이라 변경가능.
    condition= flood_conditions (flow)
    RST_THRESHOLD = 100
    if condition is None:
        return(False, "")

        
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
    



