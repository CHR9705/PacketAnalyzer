from engine import PacketData, Flow
from datetime import datetime
import os


def detect(packet: PacketData, flow: Flow):
    # 엔진이 패킷을 읽어 들일 때마다 터미널에 실시간 수집 상태를 출력합니다.
    print("실행중")
    
    # 세션 하이재킹은 TCP 프로토콜의 취약점을 노리므로 TCP가 아닌 패킷은 즉시 걸러냅니다.
    if flow.protocol != "TCP":
        return False, None

    # 패킷 유실 및 초기 트래픽 변동으로 인한 오탐을 방지하기 위해 최소 50개 이상 쌓였을 때만 분석을 시작합니다.
    if flow.packet_count < 50:
        return False, None

    # 전체 플로우 패킷 중 인증 데이터 및 응답에 사용되는 ACK 패킷의 비율을 계산합니다.
    ack_ratio = flow.ack_count / flow.packet_count
    
    # 전체 플로우 패킷 중 세션 강제 종료에 사용되는 RST 패킷의 비율을 계산합니다.
    rst_ratio = flow.rst_count / flow.packet_count

    # [🔥 핵심 탐지 논리] 세션 하이재킹 성공 시 발생하는 특이 네트워크 징후들을 정밀 저격합니다.
    if (
        flow.pps >= 50               # 1초당 유입되는 패킷 속도가 50개 이상으로 급증했고 (공격 폭주)
        and ack_ratio >= 0.75        # 세션 번호가 꼬여 서로 패킷을 재전송하는 'TCP ACK Storm' 현상으로 ACK가 75% 이상이며
        and rst_ratio >= 0.10        # 평소에 0%여야 할 연결 파괴 목적의 RST 패킷이 10% 이상 관측되고
        and flow.backward_ratio >= 0.30  # 서버가 공격자나 유저에게 대응하여 보내는 응답 비율이 30% 이상이면서
        and flow.syn_count <= 2      # 새로운 세션을 수립하는 연결 요청(SYN)은 거의 없는 유기적 하이재킹 상태일 때
    ):

        # 📊 보안 관리자(방어자) 화면에 팝업시킬 침입 탐지 대시보드를 시각적으로 출력합니다.
        print("\n" + "=" * 60)
        print("⚠️ TCP SESSION HIJACKING DETECTED ⚠️")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        print("-" * 60)

        print(f"Packet Count : {flow.packet_count}")
        print(f"ACK Count    : {flow.ack_count}")
        print(f"RST Count    : {flow.rst_count}")
        print(f"ACK Ratio    : {ack_ratio:.2%}")
        print(f"RST Ratio    : {rst_ratio:.2%}")
        print(f"PPS          : {flow.pps:.2f}")
        print(f"Backward     : {flow.backward_ratio:.2%}")
        print(f"SYN Count    : {flow.syn_count}")

        print("-" * 60)

        print("Threat Level : HIGH")
        print("Attack Type  : TCP Session Hijacking")
        print("Reason       : Abnormal ACK/RST ratio detected")

        print("=" * 60)

        # [🔒 실시간 능동 방어] 공격이 확정되는 즉시 서버가 스스로 소켓을 파괴하는 메커니즘입니다.
        try:
            # 리눅스 시스템 명령어를 호출하여 현재 탈취당한 상태인 해당 출발지/목적지 소켓 자체를 강제로 파괴(Kill)합니다.
            os.system(
                f"sudo ss -K "
                f"src {packet.src_ip} "
                f"sport = {packet.src_port} "
                f"dst {packet.dst_ip} "
                f"dport = {packet.dst_port}"
            )

            # 소켓 파괴 명령이 커널에 성공적으로 하달되었음을 알립니다. 공격자 터미널 연결이 즉시 끊어집니다.
            print("TCP Connection Closed")

        except Exception as e:
            # 시스템 권한 문제나 소켓이 이미 끊어진 경우 예외 처리 에러를 출력합니다.
            print("Connection Close Failed :", e)

        # 상위 분석 프레임워크 엔진에게 탐지 성공 여부와 공격 유형을 객체로 반환합니다.
        return (True, "TCP Session Hijacking")

    # 공격 임계치를 만족하지 않는 정상적이고 평범한 트래픽 흐름은 안전하게 통과시킵니다.
    return False, None


# =========================================================================================
# 🖥️ 가상 환경(VMware) 3대 유기적 연동 및 모의 실습 실행 주석 가이드
# =========================================================================================

# 1️⃣ VM 1 [우분투 24 / 방어 서버 및 침입 방어 시스템(IPS)]
# 서버 자체의 현재 실제 IP 주소: 192.168.72.129
# -----------------------------------------------------------------------------------------
# 터미널 창 1 (파이썬 능동 방어 엔진 가동): 
# sudo .venv/bin/python3 main.py
# 
# 터미널 창 2 (공격용 트래픽 수신 통로 개방 및 커널 패킷 실시간 흐름 분석):
# sudo tcpdump -i any tcp and port 80
# -----------------------------------------------------------------------------------------


# 2️⃣ VM 2 [우분투 22 / 터미너스 연동 공격자 호스트]
# -----------------------------------------------------------------------------------------
# 터미널 창 1 (세션 하이재킹 증후군 및 ACK 폭풍 상태를 인위적으로 결합 유입시켜 방어 엔진 격파 테스트):
# sudo hping3 -R -A -p 80 192.168.72.129 --flood
#
# 터미널 창 2 (단순 TCP Reset DoS 패킷만 대량 살포하여 방화벽 원천 차단력 테스트):
# sudo hping3 -R -p 80 192.168.72.129 --flood
# -----------------------------------------------------------------------------------------


# 3️⃣ VM 3 [우분투 26 / 웹 서비스 이용 중인 정상 사용자]
# -----------------------------------------------------------------------------------------
# 터미널 창 1 (서버와 정상 세션을 선행 수립하여 탐지 엔진 내부의 'SYN Count > 0' 조건 충족 유도):
# nc 192.168.72.129 80
# (접속 성공하여 커서가 깜빡거리면 hello_server 입력 후 엔터 전송)
# =========================================================================================
