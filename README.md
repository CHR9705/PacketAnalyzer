가이드 노션 링크 : https://www.notion.so/Scapy-393da9caea25804dad3bd0cfbacf1572?source=copy_link

# Scapy 데이터 사용법

## 코드 다운로드
이 코드를 작업 폴더에 다운로드 합니다.

직접 다운로드 받아 zip을 풀어도 되고, vscode 터미널 상에서 아래 명령을 실행해도 됩니다.

```bash
git clone https://github.com/RyunK/PacketAnalyzer.git
```

### fork
이거 하면 편하게 여러분의 github상에 코드를 저장하면서도 제 저장소에도 추가할 수 있다고 합니다.

이 github 페이지에서 버튼을 눌러 Fork 합니다.

위에서 코드를 다운로드 받았다면, 아래 명령어를 입력하여 원본 저장소와 연결합니다.

```bash
git remote add upstream https://github.com/RyunK/PacketAnalyzer.git
```

https://qkrrmsdud.tistory.com/43

저도 Fork 직접 해본적은 없고 위 블로그를 참고했습니다… 이렇게 해서 그냥 원래 하듯 개발 하다가 Pull request 하면 통합할 수 있다고 하네요.

## 코드 추가 가이드

```markdown
PacketAnalyzer
├─ detectors
│  ├─ syn_flood.py
│  └─ __init__.py
├─ engine
│  ├─ detector_loader.py
│  ├─ flow.py
│  ├─ flow_manager.py
│  ├─ packet_capture.py
│  ├─ packet_context.py
│  ├─ packet_data.py
│  ├─ processor.py
│  └─ __init__.py
├─ main.py
├─ README.md
└─ requirements.txt

```

코드를 다운로드하면 위와 같은 파일 구조가 생깁니다.

가상환경과 git 설정을 먼저 확인하세요.

설정이 완료되었다면 아래 명령어를 입력하여 **가상환경 상**에 필요한 패키지들을 설치합니다.

```bash
pip install -r requirements.txt
```

**`engine` 폴더 내부의 코드들은 기본적으로 건드리지 마세요.**

우선 `detectors` 폴더 내부에 자신이 맡은 파트에 해당하는 **파이썬 파일을 하나 만드세요**.

`syn_flood.py` 는 예시 코드가 들어있는 파일입니다. 예시를 확인했다면 삭제해도 무관합니다.

```Python
from engine import PacketData, Flow

def detect(packet: PacketData, flow: Flow):

    print('syn_flood 모듈 실행중')
    print(packet.raw_packet)
    if flow.protocol != "TCP":
        return

    if flow.syn_count > 100 and flow.pps > 50:

        print(
            "[SYN Flood]",
            packet.src_ip
        )
```

위와 같이 `detect(packet: PacketData, flow: Flow):` 함수 내부에 자신의 탐지 코드를 삽입하여 저장하면 됩니다.

`scapy`가 패킷 하나를 읽을 때마다 `detectors` 폴더 내부의 각 파일에 `detect` 함수가 있다면 이들을 호출합니다. (`engine\processor.py` 내용)

### 출력 가이드

우선 `print` 를 하면서 함수가 의도에 맞게 잘 작동하는지 테스트하세요.

추후, `dict` 형식으로 `return`받아 DB에 저장할 예정입니다.

## 코드 실행

`main.py` 파일을 실행하면 됩니다.

폴더 경로 터미널에서 다음 명령을 실행하거나,

```bash
py main.py
```

!image.png

vscode 우측 상단의 **Run Python File** 버튼을 눌러도 됩니다.

## 데이터 사용

예시 코드에서처럼 `packet.(변수명)` 이나 `flow.(변수명)`  처럼 호출하여 사용합니다.

### packet

**이번에 들어온 패킷** 1개의 데이터가 담겨 있습니다.

| **변수명** | **자료형** | **설명** | **사용 예** |
| --- | --- | --- | --- |
| timestamp | float | 패킷이 찍힌 시간 | `packet.timestamp` |
| protocol | str | 패킷의 프로토콜 (TCP or UDP) | `packet.protocol` |
| src_ip | str | 패킷의 출발지 IP | `packet.src_ip` |
| dst_ip | str | 패킷의 도착지 IP | `packet.dst_ip` |
| src_port | int | 패킷의 출발지 포트 번호 | `packet.src_port` |
| dst_port | int | 패킷의 도착지 포트 번호 | `packet.dst_port` |
| packet_size | int | 패킷의 전체 크기(Byte) | `packet.packet_size` |
| payload_size | int | 패킷의 payload 크기 (Byte) | `packet.payload_size` |
| ttl | int | ttl(time to live) 값, 라우터를 최대 몇 개 지날 수 있는지 | `packet.ttl` |
| tcp_flags | str | S, A, F 등 TCP Flags 정보 | `packet.tcp_flags` |
| raw_packet | object | Scapy로 읽은 원본 Packet 정보 
**매우 제한적으로 사용을 권장** | `packet.raw_packet`  |

### Flow

이번에 들어온 **패킷과 관련 있는 패킷들의 묶음** 및 기본적인 통계입니다.

**IP주소와 Port번호가 동일한** 패킷들을 같은 Flow라고 판단합니다.

**예시**
```markdown
1) 2.2.2.2:70 -> 192.168.0.1:80
2) 192.168.0.1:80 -> 2.2.2.2:70
3) 2.2.2.2:70 -> 192.168.0.1:100

위와 같이 통신이 이루어졌다면,
2번 패킷을 받았을 때 1,2의 정보가 들어있는 flow를 줍니다.
3번 패킷을 받았을 때의 flow 안에는 3번 패킷의 정보만 들어있습니다.
```

| **변수명** | **자료형** | **설명** | **사용 예** |
| --- | --- | --- | --- |
| flow_id | int | flow 구분자 | `flow.flow_id` |
| endpoint1_ip | str | 한 쪽의 ip  | `flow.endpoint1_ip` |
| endpoint1_port | int | 한 쪽의 port 번호 | `flow.endpoint_port` |
| endpoint2_ip | str | 다른 쪽의 ip  | `flow.endpoint2_ip` |
| endpoint2_port | int | 다른 쪽의 port 번호 | `flow.endpoint_port` |
| protocol | str | 프로토콜 (TCP or UDP) | `flow.protocol` |
| start_time | float | 첫 패킷의 timestamp | `flow.start_time` |
| last_seen | float | 마지막 패킷의 timestamp(현재 패킷) | `flow.last_seen` |
| packet_count | int | 이 flow의 패킷 횟수 | `flow.packet_count` |
| byte_count | int | 이 flow에서 주고받은 패킷 전체 byte 크기 | `flow.byte_count` |
| forward_packet_count | int | endpoint1 → endpoint2 횟수 | `flow.forward_packet_count` |
| backward_packet_count | int | endpoint2 → endpoint1 횟수 | `flow.backward_packet_count` |
| forward_byte_count | int | endpoint1 → endpoint2 패킷 전체 byte 크기 | `flow.forward_byte_count` |
| backward_byte_count | int | endpoint2 → endpoint1 패킷 전체 byte 크기 | `flow.backward_byte_count` |
| syn_count | int | TCP라면 syn 횟수 | `flow.syn_count` |
| ack_count | int | TCP라면 ack 횟수 | `flow.ack_count` |
| fin_count | int | TCP라면 fin 횟수 | `flow.fin_count` |
| rst_count | int | TCP라면 rst 횟수 | `flow.rst_count` |
| recent_packets | deque | 최신 패킷 30개 리스트 (packet과 동일한 변수 사용 가능) - 더 필요하면 추가 가능. | `flow.recent_packets[0]`  : 가장 오래된 패킷 (30번째 전) <br>`flow.recent_packets[-1]` : 가장 최신 패킷 (현재 패킷) |

| **메서드명** | **반환 자료형** | **설명** | **사용 예** |
| --- | --- | --- | --- |
| duration | float | 이 Flow가 유지된 시간(초) | `flow.duration` |
| pps | float | 초당 패킷 수 | `flow.pps` |
| bps | float | 초당 Byte 수 | `flow.bps` |
| avg_packet_size | float | 평균 패킷 크기 (Byte) | `flow.avg_packet_size` |
| forward_ratio | float | endpoint1 → endpoint2 패킷의 비율 | `flow.forward_ratio` |
| backward_ratio | float | endpoint2 → endpoint1 패킷의 비율 | `flow.backward_ratio` |
| is_one_way | bool | 한쪽 방향으로만 통신하고 있는지 | `flow.is_one_way` |