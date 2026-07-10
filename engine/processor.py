from queue import Queue
from scapy.layers.inet import IP, TCP, UDP
from .packet_data import PacketData

from .flow_manager import FlowManager

from .detector_loader import load_detectors
from .warning_manager import WarningManager
from .db.dbmodule import DBModule

import time



class PacketProcessor:

    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue
        self.flow_manager = FlowManager()
        self.detectors = load_detectors()
        self.warning_manager = WarningManager()
        self.last_flow_cleanup = time.time()

    def process_packet(self, packet):

        if IP not in packet:
            return None

        if TCP not in packet and UDP not in packet:
            return None

        protocol = "OTHER"
        src_port = None
        dst_port = None
        tcp_flags = None
        payload_size = len(bytes(packet.payload))

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
            payload_size = len(bytes(packet[TCP].payload))

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload_size = len(bytes(packet[UDP].payload))


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
        self.db_module = DBModule()
        warning_manager = self.warning_manager
        last_flush = time.time()
        while True:
            raw_packet = self.packet_queue.get()
            packet = self.process_packet(raw_packet)
            
            if packet is None:
                continue

            context = self.flow_manager.update(packet)

            if time.time() - self.last_flow_cleanup >= 5:
                self.flow_manager.remove_inactive_flows(current_time=packet.timestamp, db=self.db_module)
                self.last_flow_cleanup = time.time()

            self.db_module.insert_packet_table(
                packet.timestamp, packet.src_ip, packet.dst_ip, 
                packet.src_port, packet.dst_port, packet.protocol, 
                packet.packet_size, packet.payload_size, packet.tcp_flags)
            

            for detect in self.detectors:
                raw_result = detect(context.packet, context.flow)

                if raw_result is None:
                    result, name = False, "Unknown"
                else:
                    result, name = raw_result

                if result:
                    warning_manager.add_warning(
                        packet.timestamp,
                        packet.src_ip,
                        name
                    )

                if time.time() - last_flush >= 5:
                    warning_manager.flush(self.db_module)
                    last_flush = time.time()

            