#  Reflection Attack은 공격자가 자신의 IP를 피해자의 IP로 위조하여 여러 서버에 요청을 보내고, 
#  서버의 응답이 피해자에게 집중되도록 만드는 공격입니다.
#  UDP 트래픽을 대상으로 초당 패킷 수(PPS)와 응답 패킷 비율(Backward Ratio)을 함께 분석하여 
#  비정상적인 대량 응답이 발생하는 경우 Reflection Attack으로 탐지하도록 구현했습니다.

# UDP만 검사

from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # UDP만 검사
    if flow.protocol != "UDP":
        return False, None

    # 최소 패킷 수
    if flow.packet_count < 50:
        return False, None

    # Reflection Attack 탐지
    if (
        flow.pps >= 100
        and flow.backward_ratio >= 0.8
    ):

        print("\n" + "=" * 60)
        print("🚨 REFLECTION ATTACK DETECTED 🚨")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        print("-" * 60)

        print(f"Packet Count : {flow.packet_count}")
        print(f"PPS          : {flow.pps:.2f}")
        print(f"Forward      : {flow.forward_packet_count}")
        print(f"Backward     : {flow.backward_packet_count}")
        print(f"Backward %   : {flow.backward_ratio:.2%}")

        print("-" * 60)

        print("Threat Level : HIGH")
        print("Attack Type  : UDP Reflection Attack")
        print("Reason       : Excessive UDP response traffic")

        print("=" * 60)

        return True, "UDP Reflection Attack"

    return False, None





# 터미너스 sudo tcpdump -i any udp port 9999
# 우분투 sudo tcpdump -i any udp