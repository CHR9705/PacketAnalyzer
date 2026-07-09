from engine import PacketData, Flow
from collections import defaultdict, deque, Counter

THRESHOLD = 20
TIME_WINDOW = 20
null_scan_table = defaultdict(list)

# src_ip -> {"events": deque(), "ports": Counter()}
scan_state = defaultdict(
    lambda: {
        "events": deque(),
        "ports": Counter()
    }
)


def detect(packet: PacketData, flow: Flow):

    # NULL Scan 패킷만 검사
    if packet.tcp_flags != "":
        return (False, "")

    src_ip = packet.src_ip
    dst_port = packet.dst_port
    now = packet.timestamp

    state = scan_state[src_ip]

    # 현재 패킷 추가
    state["events"].append((now, dst_port))
    state["ports"][dst_port] += 1

    # 오래된 기록 제거
    while state["events"]:
        timestamp, port = state["events"][0]

        if now - timestamp <= TIME_WINDOW:
            break

        state["events"].popleft()

        state["ports"][port] -= 1

        if state["ports"][port] == 0:
            del state["ports"][port]

    # 서로 다른 목적지 포트 개수 확인
    if len(state["ports"]) >= THRESHOLD:
        print(f"[ALERT] NULL Scan Detected ({src_ip})")
        return (True, "NULL Scan")
    
    return (False, "")
