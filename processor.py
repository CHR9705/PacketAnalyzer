from queue import Queue
from scapy.layers.inet import IP, TCP, UDP
from packet_data import PacketData


class PacketProcessor:

    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue

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

            packet = self.packet_queue.get()

            context = self.process_packet(packet)

            if context is None:
                continue

            print(f'{context.protocol} |  {context.src_ip} | {context.src_port} -> {context.dst_ip} | {context.dst_port}')