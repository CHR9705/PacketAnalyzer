from time import time

from engine.flow import Flow
from engine.packet_context import PacketContext


class FlowManager:

    def __init__(self, flow_timeout=60, recent_window=10.0):
        self.flows = {}
        self.next_flow_id = 1
        self.flow_timeout = flow_timeout
        self.recent_window = recent_window

    def make_flow_key(self, packet):

        endpoint1 = packet.src_ip
        endpoint2 = packet.dst_ip

        endpoint1, endpoint2 = sorted([endpoint1, endpoint2])

        return (
            endpoint1,
            endpoint2,
            packet.protocol
        )

    def update(self, packet):

        key = self.make_flow_key(packet)
        flow = self.flows.get(key)
        # Flow 없으면 새로 생성
        if flow is None:
            endpoint1, endpoint2, protocol = key

            flow = Flow(
                flow_id=self.next_flow_id,

                endpoint1_ip=endpoint1,
                endpoint2_ip=endpoint2,

                protocol=protocol,

                start_time=packet.timestamp,
                last_seen=packet.timestamp
            )

            self.flows[key] = flow
            self.next_flow_id += 1

        # ----------------------------
        # Flow 정보 갱신
        # ----------------------------

        flow.last_seen = packet.timestamp

        flow.packet_count += 1
        flow.byte_count += packet.packet_size

        flow.recent_packets.append(packet)

        # window(기본 10초)보다 오래된 패킷 제거
        while (
            flow.recent_packets
            and packet.timestamp - flow.recent_packets[0].timestamp > self.recent_window
        ):
            flow.recent_packets.popleft()

        flow.update_statistics()
        # 방향 판별
        if packet.src_ip == flow.endpoint1_ip:

            flow.forward_packet_count += 1
            flow.forward_byte_count += packet.packet_size

        else:
            flow.backward_packet_count += 1
            flow.backward_byte_count += packet.packet_size

        # TCP Flag 통계
        if packet.protocol == "TCP":

            flags = packet.tcp_flags or ""

            if "S" in flags:
                flow.syn_count += 1

            if "A" in flags:
                flow.ack_count += 1

            if "F" in flags:
                flow.fin_count += 1

            if "R" in flags:
                flow.rst_count += 1

        return PacketContext(
            packet=packet,
            flow=flow
        )
    
    def remove_inactive_flows(self, db, current_time, timeout=10):
        now = current_time

        remove_keys = [
            key
            for key, flow in self.flows.items()
            if now - flow.last_seen > timeout
        ]

        for key in remove_keys:
            flow = self.flows[key]
            db.insert_flow_table(flow.start_time, flow.last_seen, flow.endpoint1_ip, flow.endpoint2_ip, flow.packet_count, flow.byte_count,
                          flow.protocol, flow.syn_count, flow.ack_count, flow.fin_count, flow.rst_count)
            del self.flows[key]