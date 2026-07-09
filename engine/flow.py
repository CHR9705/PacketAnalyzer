from dataclasses import dataclass, field
from collections import Counter, deque


@dataclass
class Flow:
    flow_id: int

    # 양방향 Endpoint
    endpoint1_ip: str

    endpoint2_ip: str

    protocol: str

    # 시간
    start_time: float
    last_seen: float

    # 전체 통계
    packet_count: int = 0
    byte_count: int = 0

    # 방향별 통계
    forward_packet_count: int = 0
    backward_packet_count: int = 0

    forward_byte_count: int = 0
    backward_byte_count: int = 0

    # TCP Flag 통계
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    # 최근 패킷
    recent_packets: deque = field(default_factory=deque)

    static_pps: float = 0.0
    static_bps: float = 0.0


    # ---------- 계산 속성 ----------

    @property
    def duration(self) -> float:
        """Flow가 유지된 시간(초)"""
        return max(self.last_seen - self.start_time, 0)

    @property
    def pps(self) -> float:
        """
        최근 1초 동안의 Packets 수
        """
        return self.static_pps

    @property
    def bps(self) -> float:
        """Bytes Per Second"""

        return self.static_bps

    @property
    def avg_packet_size(self) -> float:
        """평균 패킷 크기(Byte)"""
        if self.packet_count == 0:
            return 0

        return self.byte_count / self.packet_count

    @property
    def forward_ratio(self) -> float:
        """정방향 패킷 비율"""
        if self.packet_count == 0:
            return 0

        return self.forward_packet_count / self.packet_count

    @property
    def backward_ratio(self) -> float:
        """역방향 패킷 비율"""
        if self.packet_count == 0:
            return 0

        return self.backward_packet_count / self.packet_count

    @property
    def is_one_way(self) -> bool:
        """한쪽 방향으로만 통신하는 Flow인지"""
        return (
            self.forward_packet_count == 0
            or self.backward_packet_count == 0
        )
    

    def get_dst_port_counter(self, seconds, src_ip) -> Counter:
        """
        특정 소스 IP에서 전송된 최근 패킷들의 목적지 포트별 접근 횟수를 반환.
        @param seconds: 최근 몇 초간의 패킷을 고려할지(최대 10초)
        @param src_ip: 소스 IP 주소
        @return: Counter 객체, 키: 목적지 포트, 값: 접근 횟수 counter[80]하면 80번 포트에 접근한 횟수 반환
        """
        counter = Counter()

        for packet in self.recent_packets:
            if packet.src_ip == src_ip and packet.timestamp >= self.last_seen - seconds:
                counter[packet.dst_port] += 1

        return counter
    
    def get_dst_unique_ports(self, seconds, src_ip) -> set:
        """
        특정 소스 IP에서 전송된 최근 패킷들의 목적지 포트들의 종류를 반환. 
        @param seconds: 최근 몇 초간의 패킷을 고려할지(최대 10초)
        @param src_ip: 소스 IP 주소
        @return: 고유한 목적지 포트의 집합
        """
        unique_ports = set()

        for packet in self.recent_packets:
            if packet.src_ip == src_ip and packet.timestamp >= self.last_seen - seconds:
                unique_ports.add(packet.dst_port)

        return unique_ports
    

    def get_recent_flag_counter(self, seconds) -> Counter:
        """
        최근 {seconds}초동안의 TCP 패킷들의 Flag별 접근 횟수를 반환.
        @param seconds: 최근 몇 초간의 패킷을 고려할지(최대 10초)
        @return: Counter 객체, 키: TCP Flag, 값: 접근 횟수 counter
        """
        counter = Counter()

        for packet in self.recent_packets:

            if packet.protocol != "TCP":
                continue
            
            if packet.timestamp < self.last_seen - seconds:
                continue
            if not packet.tcp_flags:
                counter["N"] += 1
            else: 
                for flag in packet.tcp_flags:
                    counter[flag] += 1

        return counter
    
    def get_recent_packets_by_flag(self, seconds, flag: str):
        """
        최근 {seconds}초동안의 TCP 패킷 중 특정 Flag를 가진 패킷들을 반환.
        @param seconds: 최근 몇 초간의 패킷을 고려할지(최대 10초)
        @param flag: TCP Flag (예: "S", "A", "F", "R")
        @return: 해당 Flag를 가진 PacketData 객체들의 리스트
        """
        return [
            packet
            for packet in self.recent_packets
            if packet.protocol == "TCP"
            and (packet.tcp_flags or "") == flag
            and packet.timestamp >= self.last_seen - seconds
        ]
    
    def get_avg_packet_size(self, seconds: float):

        packets = self.get_packets(seconds)

        if not packets:
            return 0

        return (
            sum(packet.packet_size for packet in packets)
            / len(packets)
        )

    def get_packets(self, seconds: float | None = None):

        if seconds is None:
            return list(self.recent_packets)

        cutoff = self.last_seen - seconds

        return [
            packet
            for packet in self.recent_packets
            if packet.timestamp >= cutoff
        ]

    def update_statistics(self):
        self.static_pps = sum(
            1
            for packet in self.recent_packets
            if packet.timestamp >= self.last_seen - 1
        )

        self.static_bps = sum(
            packet.packet_size
            for packet in self.recent_packets
            if packet.timestamp >= self.last_seen - 1
        )
