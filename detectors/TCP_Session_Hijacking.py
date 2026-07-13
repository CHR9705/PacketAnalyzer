
from engine import PacketData, Flow
from datetime import datetime


def detect(packet: PacketData, flow: Flow):

    # TCP만 검사
    if flow.protocol != "TCP":
        return False, None

    # 패킷이 너무 적으면 분석하지 않음
    if flow.packet_count < 30:
        return False, None

    # RST 비율
    rst_ratio = flow.rst_count / flow.packet_count

    # ACK 비율
    ack_ratio = flow.ack_count / flow.packet_count

    # Session Hijacking 의심
    if (
        flow.syn_count > 0
        and flow.pps >= 100
        and ack_ratio >= 0.7
        and rst_ratio >= 0.2
    ):

        print("\n" + "=" * 60)
        print("⚠️ TCP SESSION HIJACKING SUSPECTED ⚠️")
        print("=" * 60)

        print(f"Time         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP    : {packet.src_ip}")
        print(f"Destination  : {packet.dst_ip}")
        print(f"Protocol     : {flow.protocol}")

        print("-" * 60)

        print(f"Packet Count : {flow.packet_count}")
        print(f"SYN Count    : {flow.syn_count}")
        print(f"ACK Count    : {flow.ack_count}")
        print(f"RST Count    : {flow.rst_count}")
        print(f"ACK Ratio    : {ack_ratio:.2%}")
        print(f"RST Ratio    : {rst_ratio:.2%}")
        print(f"PPS          : {flow.pps:.2f}")

        print("-" * 60)

        print("Threat Level : MEDIUM")
        print("Attack Type  : TCP Session Hijacking")
        print("Reason       : Abnormal TCP ACK/RST behavior")

        print("=" * 60)

        return True, "TCP Session Hijacking"

    return False, None

# sudo hping3 -R -p 443 192.168.72.129 --fast --count 1000 공격코드