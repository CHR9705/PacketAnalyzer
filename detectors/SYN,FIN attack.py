"""
syn_fin_scan_attacker.py

SYN Scan / FIN Scan 탐지 모듈(detect 함수)을 테스트하기 위한 공격 발생기.

*** 주의 ***
반드시 본인이 소유하거나 명시적으로 테스트 허가를 받은 시스템에서만
사용할 것. 격리된 VMware 내부망(공격자 VM -> 탐지 대상 VM)처럼
외부로 나가지 않는 환경에서만 실행해야 한다.

무엇을 하는 스크립트인가:
- scapy로 SYN 플래그만 켜진 패킷, 또는 FIN 플래그만 켜진 패킷을
  만들어서 TARGET_IP의 여러 포트(START_PORT~END_PORT)에 순서대로 쏜다.
- 탐지 코드가 실제로 SYN Scan / FIN Scan을 경고로 잡아내는지
  확인하는 용도.

사용 방법:
    sudo python3 syn_fin_scan_attacker.py --syn   # SYN 스캔만
    sudo python3 syn_fin_scan_attacker.py --fin   # FIN 스캔만
    sudo python3 syn_fin_scan_attacker.py --both  # SYN 후 FIN (옵션 없이 실행해도 동일)

주요 설정값 (파일 상단에서 조절 가능):
- TARGET_IP              : 탐지 대상 VM의 IP. 실제 테스트 환경에 맞게 반드시 변경.
- START_PORT / END_PORT  : 스캔할 포트 범위. 기본 1~29번(총 29개, PORT_THRESHOLD=10을 넉넉히 넘김).
- DELAY_BETWEEN_PACKETS  : 패킷 사이 간격(초). 늘리면 "느린 스캔이라 탐지가 안 되는" 상황도 재현 가능.
- TTL                    : 패킷의 TTL 값. 기본 64(일반적인 Linux 기본값).
- SOURCE_IP              : None이면 OS가 자동으로 출발지 IP를 채움. 값을 넣으면 그 IP로 위조(spoofing).
- USE_RANDOM_SOURCE_PORT : True면 매 패킷마다 출발지 포트를 무작위로 사용, False면 FIXED_SOURCE_PORT 고정.
- SCAN_GAP_SECONDS       : SYN과 FIN을 모두 실행할 때 그 사이에 쉬는 시간.
                           탐지 코드의 TIME_WINDOW(5초)와 겹치지 않도록 5초보다 크게(기본 6초) 잡음.

구현 노트 (--syn --fin 동시 사용 시 딜레이 처리):
- main()에서 args.both만 보고 딜레이를 넣으면, "--syn --fin"을 동시에 줬을 때
  (args.both는 False인 채로 둘 다 True인 경우) 딜레이 없이 SYN 직후 바로
  FIN이 나가버리는 문제가 있었다. 그래서 run_syn = args.syn or args.both,
  run_fin = args.fin or args.both 로 "이번에 실제로 실행될 스캔이 뭔지"를
  먼저 정리한 뒤, run_syn and run_fin일 때만(즉 SYN과 FIN이 둘 다 실행될
  예정일 때만) 사이에 SCAN_GAP_SECONDS만큼 쉬도록 만들었다. 이렇게 하면
  --both든 --syn --fin이든 항상 같은 결과가 나온다.
"""

from scapy.all import IP, TCP, send, RandShort
import argparse
import time

# ----------------------------
# 기본 설정
# ----------------------------
TARGET_IP = "192.168.0.10"
START_PORT = 1
END_PORT = 29
DELAY_BETWEEN_PACKETS = 0.05
TTL = 64

# None이면 OS가 자동으로 Source IP 선택
SOURCE_IP = None

# True이면 랜덤 Source Port 사용
# False이면 FIXED_SOURCE_PORT 사용
USE_RANDOM_SOURCE_PORT = False
FIXED_SOURCE_PORT = 40000

# SYN 스캔과 FIN 스캔을 모두 실행할 때, 둘 사이에 쉬어줄 시간(초).
# 탐지 코드의 TIME_WINDOW(5초)보다 살짝 크게 잡아야 두 스캔이
# 하나의 탐지 윈도우에 섞이지 않는다.
SCAN_GAP_SECONDS = 6

SEPARATOR = "=" * 60  # 헤더/푸터에서 반복 사용하는 구분선


def create_packet(dst_ip, dst_port, flags):
    """
    TCP 패킷 생성
    """
    if USE_RANDOM_SOURCE_PORT:
        sport = RandShort()
    else:
        sport = FIXED_SOURCE_PORT

    ip = IP(dst=dst_ip, ttl=TTL)
    if SOURCE_IP is not None:
        ip.src = SOURCE_IP

    tcp = TCP(
        sport=sport,
        dport=dst_port,
        flags=flags
    )
    return ip / tcp


def send_scan(target_ip, start_port, end_port, flags, label):
    """
    지정한 플래그(S/F)를 이용하여 여러 포트를 순차적으로 스캔한다.
    """
    port_count = end_port - start_port + 1

    # 헤더 5줄을 print 5번이 아니라 문자열 하나로 묶어서 한 번에 출력
    print(
        f"{SEPARATOR}\n"
        f"{label} 시작\n"
        f"Target IP     : {target_ip}\n"
        f"Port Range    : {start_port} ~ {end_port}\n"
        f"Packet Count  : {port_count}\n"
        f"{SEPARATOR}"
    )

    sent = 0
    for port in range(start_port, end_port + 1):
        packet = create_packet(target_ip, port, flags)
        send(packet, verbose=False)
        sent += 1
        print(f"[{sent:02d}] {flags} -> Port {port}")
        time.sleep(DELAY_BETWEEN_PACKETS)

    # 푸터도 마찬가지로 한 번에 출력
    print(
        f"\n{label} 완료\n"
        f"총 {sent}개의 패킷 전송\n"
        f"{SEPARATOR}\n"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--syn",
        action="store_true",
        help="SYN Scan 실행"
    )
    parser.add_argument(
        "--fin",
        action="store_true",
        help="FIN Scan 실행"
    )
    parser.add_argument(
        "--both",
        action="store_true",
        help="SYN 후 FIN 실행"
    )
    args = parser.parse_args()

    # 아무 옵션도 안 주면 둘 다 실행
    if not (args.syn or args.fin or args.both):
        args.both = True

    run_syn = args.syn or args.both
    run_fin = args.fin or args.both

    if run_syn:
        send_scan(
            TARGET_IP,
            START_PORT,
            END_PORT,
            flags="S",
            label="SYN Scan"
        )

    # SYN과 FIN이 둘 다 실행될 예정일 때만 사이에 쉬어준다.
    # (--both뿐 아니라 --syn --fin을 동시에 줬을 때도 동일하게 적용되도록
    #  args.both 대신 run_syn/run_fin 조합으로 판단한다)
    if run_syn and run_fin:
        print(f"[대기] 탐지 윈도우가 겹치지 않도록 {SCAN_GAP_SECONDS}초 대기...\n")
        time.sleep(SCAN_GAP_SECONDS)

    if run_fin:
        send_scan(
            TARGET_IP,
            START_PORT,
            END_PORT,
            flags="F",
            label="FIN Scan"
        )


if __name__ == "__main__":
    main()