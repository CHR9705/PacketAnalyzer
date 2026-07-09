from collections import defaultdict, deque, Counter
from dataclasses import dataclass


@dataclass
class AmplificationResult:
    victim_ip: str
    packet_count: int
    total_bytes: int
    unique_servers: int
    top_servers: list

    def __str__(self):
        return (
            f"Victim: {self.victim_ip}"
            f"Responses: {self.packet_count}"
            f"Traffic: {self.total_bytes:,} Bytes "
            f"DNS Servers: {self.unique_servers} "
        )


class AmplificationDetector:

    def __init__(self, time_window: float):

        self.time_window = time_window

        self.state = defaultdict(
            lambda: {
                "events": deque(),
                "servers": Counter(),
                "total_bytes": 0
            }
        )

    def add_packet(self, packet):

        victim = packet.dst_ip
        state = self.state[victim]

        # 현재 패킷 저장
        state["events"].append(packet)
        state["servers"][packet.src_ip] += 1
        state["total_bytes"] += packet.packet_size

        # 오래된 패킷 제거
        state = self.remove_old_packets(state, packet)

        return AmplificationResult(
            victim_ip=victim,
            packet_count=len(state["events"]),
            total_bytes=state["total_bytes"],
            unique_servers=len(state["servers"]),
            top_servers=state["servers"].most_common(5)
        )
    
    def remove_old_packets(self, state, packet):
        while state["events"]:

            oldest = state["events"][0]

            if packet.timestamp - oldest.timestamp <= self.time_window:
                break

            oldest = state["events"].popleft()

            state["servers"][oldest.src_ip] -= 1

            if state["servers"][oldest.src_ip] == 0:
                del state["servers"][oldest.src_ip]

            state["total_bytes"] -= oldest.packet_size
        return state
