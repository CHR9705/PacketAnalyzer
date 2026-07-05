from flow import Flow
from packet_context import PacketContext


class FlowManager:

    def __init__(self):
        self.flows = {}

    def update(self, packet):

        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol
        )

        flow = self.flows.get(key)

        if flow is None:

            flow = Flow(
                flow_id=str(len(self.flows) + 1),

                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,

                src_port=packet.src_port,
                dst_port=packet.dst_port,

                protocol=packet.protocol,

                start_time=packet.timestamp,
                last_seen=packet.timestamp
            )

            self.flows[key] = flow

        flow.last_seen = packet.timestamp

        flow.packet_count += 1
        flow.byte_count += packet.packet_size

        flow.recent_packets.append(packet)

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