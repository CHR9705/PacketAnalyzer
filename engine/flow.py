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
    recent_packets: deque = field(default_factory=lambda: deque(maxlen=50))


    # ---------- 계산 속성 ----------

    @property
    def duration(self) -> float:
        """Flow가 유지된 시간(초)"""
        return max(self.last_seen - self.start_time, 0)

    @property
    def pps(self) -> float:
        """Packets Per Second"""
        if self.duration == 0:
            return float(self.packet_count)

        return self.packet_count / self.duration

    @property
    def bps(self) -> float:
        """Bytes Per Second"""
        if self.duration == 0:
            return float(self.byte_count)

        return self.byte_count / self.duration

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
    

    def get_dst_port_counter(self, src_ip) -> Counter:
        """
        특정 소스 IP에서 전송된 패킷들의 목적지 포트별 접근 횟수를 반환. recent_packets를 기반으로 계산하므로 최근 50개 패킷에서만 산정됨.
        @param src_ip: 소스 IP 주소
        @return: Counter 객체, 키: 목적지 포트, 값: 접근 횟수 counter[80]하면 80번 포트에 접근한 횟수 반환
        """
        counter = Counter()

        for packet in self.recent_packets:
            if packet.src_ip == src_ip:
                counter[packet.dst_port] += 1

        return counter
    
    def get_dst_unique_ports(self, src_ip) -> set:
        """
        특정 소스 IP에서 전송된 패킷들의 목적지 포트들의 종류를 반환. recent_packets를 기반으로 계산하므로 최근 50개 패킷에서만 산정됨.
        @param src_ip: 소스 IP 주소
        @return: 고유한 목적지 포트의 집합
        """
        unique_ports = set()

        for packet in self.recent_packets:
            if packet.src_ip == src_ip:
                unique_ports.add(packet.dst_port)

        return unique_ports