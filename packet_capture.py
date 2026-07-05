from scapy.all import sniff
from queue import Queue


class PacketCapture:

    def __init__(self, packet_queue: Queue):
        self.packet_queue = packet_queue

    def _callback(self, packet):
        self.packet_queue.put(packet)

    def start(self):
        sniff(
            prn=self._callback,
            store=False
        )