# Packet Analyzer

> **Scapy 기반 실시간 네트워크 패킷 분석 및 공격 탐지 시스템**

Packet Analyzer는 실시간으로 네트워크 패킷을 수집하고 다양한 네트워크 공격을 탐지하며, 공격 정보를 시각화하고 자동 차단 기능을 제공하는 네트워크 보안 모니터링 시스템입니다.

프로젝트는 **패킷 분석 엔진(Engine)** 과 **웹 대시보드(Streamlit)** 를 분리하여 동작하도록 설계되었으며, SQLite를 이용하여 별도의 데이터베이스 서버 없이 실행할 수 있도록 구성되었습니다.

---

## 실행 방법

### 주의사항

방화벽 관련 기능은 리눅스에서만 구현되어 있습니다. 윈도우에서 실행해도 오류가 나지는 않지만, 실제로 패킷이 방화벽에 차단되지 않습니다. 


### 1. 패키지 설치

```bash
pip install -r requirements.txt
```

### 2. Discord 봇 및 .env 설정

`.env` 파일 설정이 필요합니다.

[디스코드 개발자 포탈](https://discord.com/developers/)에 접속하여 디스코드 봇을 생성합니다. 


```
DISCORD_TOKEN = YOUR_BOT_INSTALL_LINK
auth_id = YOUR_DISCORD_USER_ID_1, YOUR_DISCORD_USER_ID_2, ...
```

+ `DISCORD_TOKEN`: **애플리케이션 - 설치 - 설치 링크**를 복사하여 저장합니다.
+ `auth_id`: Discord에서 개발자 모드를 키고 **사용자 프로필 클릭 - 사용자 ID 복사**하여 저장합니다.
   * 여러 개의 계정에 전송하려면 **쉼표(,)** 로 구분합니다.


### 3. Engine 실행

```bash
python main.py
```


### 4. Dashboard 실행

```bash
streamlit run index.py
```


### 5. 전체 실행

```bash
start_all.bat
```

---

## 주요 기능

* 실시간 TCP/UDP 패킷 수집
* Flow 기반 패킷 관리
* 다양한 네트워크 공격 탐지
* 공격 위험도(CVSS 기반) 점수 계산
* 공격 이력 관리
* 공격 자동 차단(iptables)
* 직접 ip 차단(iptables)
* Discord 알림 전송
* Streamlit 기반 모니터링 대시보드
* 승인 기반 IP 화이트리스트 관리
* 공격 로그 조회 및 통계 제공

---
## Dependency

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-0080FF?style=for-the-badge&logo=wireshark&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![iptables](https://img.shields.io/badge/iptables-D00000?style=for-the-badge&logo=linux&logoColor=white)
![Discord](https://img.shields.io/badge/Discord%20Bot-5865F2?style=for-the-badge&logo=discord&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Linux%20(Ubuntu)-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)


---

## 시스템 구조

```
                     +----------------------+
                     |  Network Interface   |
                     +----------+-----------+
                                |
                           Scapy Capture
                                |
                                ▼
                    +-----------------------+
                    | Packet Capture Thread |
                    +-----------+-----------+
                                |
                                ▼
                    +-----------------------+
                    | Packet Processor      |
                    +-----------+-----------+
                                |
          +---------------------+---------------------+
          |                     |                     |
          ▼                     ▼                     ▼
   Flow Manager          Detector Loader      Score Calculator
          |                     |                     |
          +---------------------+---------------------+
                                |
                                ▼
                     Warning Manager
                                |
            +-------------------+------------------+
            |                                      |
            ▼                                      ▼
      SQLite Database                     Discord Alert
            |
            ▼
     Firewall Worker
            |
            ▼
        iptables
```

---

## 시스템 구성

본 프로젝트는 크게 **두 개의 프로세스**로 구성됩니다.

### 1. Packet Analyzer Engine

실시간 패킷 분석을 담당하는 핵심 프로세스입니다.

패킷 캡처 및 공격 탐지, iptables 방화벽 규칙 생성, Discord 알림 등의 일을 하는 중심 엔진 프로세스 입니다.

### 2. Streamlit Dashboard

사용자가 시스템 상태를 확인하고 관리하는 웹 인터페이스입니다.

실시간 패킷 및 공격 현황을 볼 수 있는 Dashboard, IP 차단 관리, 회원가입 등 접근 제어를 수행합니다.


---

## 디렉터리 구조

```
PacketAnalyzer
│
├── engine/                # 패킷 분석 엔진
│   ├── db/                # SQLite Repository 접근 모듈
│   ├── discord/           # Discord 알림
│   ├── packet_capture.py  # Scapy 캡처
│   ├── processor.py       # 패킷 처리
│   ├── flow_manager.py    # Flow 관리
│   ├── detector_loader.py # 탐지기 로드
│   ├── warning_manager.py # 공격 관리
│   ├── firewall_worker.py # 자동 차단
│   ├── iptables.py        # iptables 제어
│   └── score_calculator.py# 위험도 계산
│
├── detectors/             # 공격 탐지 모듈
│
├── webpages/              # Streamlit 페이지
│   ├── pages/
│   ├── css/
│   └── functions/
│
├── statics/               # 이미지 및 정적 파일
│
├── index.py               # Streamlit 시작점
├── main.py                # Engine 시작점
└── requirements.txt
```



### engine/

패킷 분석 시스템의 핵심 로직이 위치합니다.

### packet_capture.py

Scapy를 이용하여 실시간 패킷을 캡처합니다.

### processor.py

캡처된 패킷을 분석하여 Flow 생성 및 탐지를 수행하는 메인 스레드입니다.

### flow_manager.py

TCP/UDP Flow를 관리합니다. 

### detector_loader.py

모든 탐지 모듈을 동적으로 로드합니다.

### warning_manager.py

탐지된 공격을 관리하고 중복 공격을 병합합니다.

### firewall_worker.py

웹으로부터 받은 차단 요청을 감시하여 iptables 규칙을 적용합니다. 별도의 스레드를 차지합니다.

### score_calculator.py

탐지된 공격에 대해 CVSS 기반 위험도를 계산합니다.

### auto_block.py

score를 기반으로 공격이 탐지된 packet을 자동으로 차단합니다.


### engine/db/

SQLite 접근을 위한 모듈입니다.

* packets_repo
* flows_repo
* warnings_repo
* blocked_packets_repo
* black_white_list_repo

### engine/discord/

Discord Bot을 이용하여 탐지 결과를 실시간으로 전송합니다.



### detectors/

각 공격별 탐지 알고리즘이 독립적인 모듈로 구현되어 있으며, 새로운 공격을 추가하려면 detector 함수를 포함한 파일을 작성하면 됩니다.


### webpages/

Streamlit으로 구현된 Dashboard 및 GUI용 웹앱입니다.


---


## 데이터 흐름

```
패킷 캡처 → 흐름 분석 → 경고 처리 → Sqlite ↔ 대시보드
                        ⇣         ↳ 방화벽 차단
                   자동 방화벽 등록
```



## 데이터베이스

SQLite를 사용하여 별도의 DBMS 설치 없이 실행할 수 있도록 구성하였습니다.

엔진 관련 테이블들

* packets
* flows
* warnings
* blocked_packets
* blacklist
* whitelist

로그인 및 권한 관리 관련 테이블들

* users
* sessions
* notifications
* role_requests
* messages
* login_attempts
* audit_log


## 설계 특징

* Engine과 Dashboard를 프로세스 단위로 분리하여 UI와 패킷 분석을 독립적으로 수행
* Flow 기반 분석을 적용하여 세션 단위의 탐지 지원
* 공격 탐지기를 모듈화하여 새로운 탐지 알고리즘을 쉽게 추가 가능
* Repository 패턴을 적용하여 데이터 접근 로직을 분리
* SQLite를 사용하여 별도의 서버 없이 실행 가능
* 자동 차단 기능과 Dashboard를 데이터베이스를 통해 느슨하게 결합하여 유지보수성 향상



## 향후 개선 사항

* 데이터 흐름 개선
   - DB 접근 축소를 통한 성능 향상
* 머신러닝 기반 이상 탐지
* 다양한 IDS 규칙 지원
* Docker 기반 배포
   - 인프라형 프로그램들도 간편히 설치할 수 있도록


## 라이선스

본 프로젝트는 학습 및 연구 목적으로 개발되었습니다.
