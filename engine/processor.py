from queue import Queue
from scapy.layers.inet import IP, TCP, UDP
from .packet_data import PacketData

from .flow_manager import FlowManager

from .detector_loader import load_detectors


class PacketProcessor:

    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue
        self.flow_manager = FlowManager()
        self.detectors = load_detectors()

    def process_packet(self, packet):

        if IP not in packet:
            return None

        if TCP not in packet and UDP not in packet:
            return None

        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        payload_size = len(bytes(packet.payload))

        return PacketData(
            timestamp=packet.time,

            protocol=protocol,

            src_ip=packet[IP].src,
            dst_ip=packet[IP].dst,

            src_port=src_port,
            dst_port=dst_port,

            packet_size=len(packet),
            payload_size=payload_size,

            ttl=packet[IP].ttl,

            tcp_flags=tcp_flags,

            raw_packet=packet
        )

    def run(self):
        while True:
            raw_packet = self.packet_queue.get()
            packet = self.process_packet(raw_packet)

            if packet is None:
                continue

            context = self.flow_manager.update(packet)

            # print(
            #     context.packet.src_ip,
            #     "->",
            #     context.packet.dst_ip,
            #     context.flow.packet_count
            # )

            for detect in self.detectors:
                detect(context.packet, context.flow)

            