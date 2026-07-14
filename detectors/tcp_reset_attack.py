#  RST 개수만으로 공격을 판단하지 않았습니다. 
#  정상적인 TCP 통신에서도 RST가 발생할 수 있기 때문입니다. 
#  따라서 TCP 여부, 전체 패킷 대비 RST 비율(RST Ratio), 초당 패킷 수(PPS),   
#  그리고 정상적인 TCP 연결(SYN)이 있었는지를 함께 확인하여 TCP Reset Attack을 탐지하도록 구현했습니다.

from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # TCP 패킷만 검사
    if flow.protocol != "TCP":
        return

    # 패킷이 너무 적으면 판단하지 않음
    if flow.packet_count < 20:
        return

    # 전체 패킷 대비 RST 비율
    rst_ratio = flow.rst_count / flow.packet_count

    # ack_count가 Flow에 없을 경우를 대비
    ack_count = getattr(flow, "ack_count", 0)

    # 전체 패킷 대비 ACK 비율
    ack_ratio = ack_count / flow.packet_count

    # 1. 정상 연결 이후 RST가 다량 발생한 경우
    session_reset_attack = (
        flow.syn_count > 0
        and flow.pps >= 50
        and flow.rst_count >= 20
        and rst_ratio >= 0.6
    )

    # 2. SYN 없이 RST 패킷만 대량 전송하는 RST Flood
    rst_flood_attack = (
        flow.syn_count == 0
        and flow.pps >= 50
        and flow.rst_count >= 20
        and rst_ratio >= 0.8
    )

    # 두 조건 중 하나라도 만족하면 탐지
    if session_reset_attack or rst_flood_attack:

        if session_reset_attack:
            attack_type = "TCP Reset Attack"
        else:
            attack_type = "TCP RST Flood"

        print("\n" + "=" * 60)
        print("🚨 TCP RESET ATTACK DETECTED 🚨")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        # 포트 정보가 존재하는 경우 출력
        if hasattr(packet, "src_port"):
            print(f"Source Port  : {packet.src_port}")

        if hasattr(packet, "dst_port"):
            print(f"Dest Port    : {packet.dst_port}")

        print("-" * 60)

        print(f"Packets      : {flow.packet_count}")
        print(f"SYN Count    : {flow.syn_count}")
        print(f"ACK Count    : {ack_count}")
        print(f"RST Count    : {flow.rst_count}")
        print(f"RST Ratio    : {rst_ratio:.2%}")
        print(f"ACK Ratio    : {ack_ratio:.2%}")
        print(f"PPS          : {flow.pps:.2f}")

        print("-" * 60)

        print("Threat Level : HIGH")
        print(f"Attack Type  : {attack_type}")
        print("Status       : Suspicious TCP Reset Traffic Detected")

        print("=" * 60)



# 터미너스(공격) sudo hping3 -R -p 80 192.168.72.129 --flood
# 우분투(방어) sudo tcpdump -i any tcp or sudo tcpdump -i any host 192.168.72.129