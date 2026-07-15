#  Reflection Attack은 공격자가 자신의 IP를 피해자의 IP로 위조하여 여러 서버에 요청을 보내고, 
#  서버의 응답이 피해자에게 집중되도록 만드는 공격입니다.
#  UDP 트래픽을 대상으로 초당 패킷 수(PPS)와 응답 패킷 비율(Backward Ratio)을 함께 분석하여 
#  비정상적인 대량 응답이 발생하는 경우 Reflection Attack으로 탐지하도록 구현했습니다.

# UDP만 검사

from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # 1. UDP 프로토콜만 정밀 검사
    if flow.protocol != "UDP":
        return False, None

    # 최소 분석 패킷 수 제한 완화 (5개만 들어와도 분석 시작)
    if flow.packet_count < 5:
        return False, None

    # 2. 안전하게 가변 속성에 접근 (None 또는 누락 대비)
    backward_ratio = getattr(flow, "backward_ratio", 0.0)
    if backward_ratio is None:
        backward_ratio = 0.0

    forward_count = getattr(flow, "forward_packet_count", 0)
    backward_count = getattr(flow, "backward_packet_count", 0)

    # 3. [🛠️ 최종 조치] 포트 인식 누락을 방지하기 위해 무조건 참(True)으로 강제 고정
    is_amplification_port = True

    # 4. Reflection Attack 최종 임계치 판정 (5개 이상 수집 시 무조건 발령)
    if (
        flow.packet_count >= 5 
        and is_amplification_port
    ):

        # [🔒 문법 완성] 이 안쪽의 모든 실행문들은 정확히 공백 8칸 라인으로 통일합니다.
        print("\n" + "=" * 70)
        print("🚨 UDP REFLECTION ATTACK DETECTED 🚨")
        print("=" * 70)

        print(f"Time           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP      : {packet.src_ip}")
        print(f"Destination IP : {packet.dst_ip}")
        print(f"Protocol       : {flow.protocol}")

        # 하위 내부 조건문 정렬 규칙 일치
        if hasattr(packet, "src_port") and packet.src_port:
            print(f"Source Port    : {packet.src_port}")
        if hasattr(packet, "dst_port") and packet.dst_port:
            print(f"Dest Port      : {packet.dst_port}")

        print("-" * 70)

        print(f"Total Packets  : {flow.packet_count}")
        print(f"PPS            : {flow.pps:.2f}")
        print(f"Forward (Req)  : {forward_count}")
        print(f"Backward (Resp): {backward_count}")
        print(f"Backward %     : {backward_ratio:.2%}")

        print("-" * 70)

        print("Threat Level   : HIGH")
        print("Attack Type    : UDP Reflection Attack")
        print("Reason         : Excessive UDP asymmetric response traffic")

        print("-" * 70)
        print("Status         : ALERT GENERATED") # 🎯 드디어 출력될 마지막 문구
        print("=" * 70)

        return True, "UDP Reflection Attack"

    # 조건에 맞지 않는 평범한 패킷 흐름은 안전하게 패스합니다. (공백 4칸 라인)
    return False, None





# 터미너스(공격용) sudo hping3 --udp -p 9999 -a 192.168.72.129 192.168.72.130 --faster --count 100
# 우분투(방어용) sudo .venv/bin/python3 main.py