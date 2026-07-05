from scapy.all import sniff
from queue import Queue


class PacketCapture:

    def __init__(self, packet_queue: Queue, bpf_filter="tcp or udp"):
        self.packet_queue = packet_queue
        self.bpf_filter = bpf_filter

    def _callback(self, packet):
        self.packet_queue.put(packet)

    def start(self):
        sniff(
            filter=self.bpf_filter,
            prn=self._callback,
            store=False
        )
