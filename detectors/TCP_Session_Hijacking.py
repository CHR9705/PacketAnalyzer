from engine import PacketData, Flow
from datetime import datetime
import os


def detect(packet: PacketData, flow: Flow):
    print("실행중")
    if flow.protocol != "TCP":
        return False, None

    if flow.packet_count < 50:
        return False, None

    ack_ratio = flow.ack_count / flow.packet_count
    rst_ratio = flow.rst_count / flow.packet_count

    if (
        flow.pps >= 50
        and ack_ratio >= 0.75
        and rst_ratio >= 0.10
        and flow.backward_ratio >= 0.30
        and flow.syn_count <= 2
    ):

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

        try:
            os.system(
                f"sudo ss -K "
                f"src {packet.src_ip} "
                f"sport = {packet.src_port} "
                f"dst {packet.dst_ip} "
                f"dport = {packet.dst_port}"
            )

            print("TCP Connection Closed")

        except Exception as e:
            print("Connection Close Failed :", e)

        return (True, "TCP Session Hijacking")

    return False, None