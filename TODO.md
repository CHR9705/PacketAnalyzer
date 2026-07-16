## 작업 목록
- [ ] 웹페이지에서 차단 기능 구현 > pull request
- [ ] 웹페이지 tts 구현
- [ ] 웹페이지에서 로그인 기능 구현
- [ ] Streamlit에서 차단됨 로그들 보여주기
- [ ] Streamlit에서 경고 확인


## 완료된 작업 목록
- [x] 저장소·dev 개설, 팀원 초대, 보호 규칙 — 팀장 RyunK
- [x] 코드 골격 작성 — 팀장 RyunK
- [x] amplification detection 개발 — 팀장 RyunK
- [x] packets, warnings, flows를 DB에 저장 - 팀장 RyunK
- [x] Scan 탐지 모듈
- [x] Flood 탐지 모듈
- [x] Discord 모듈
- [x] 웹페이지 대시보드 개발
- [x] 웹페이지에서 ip에 따른 지도 구현
- [x] 웹페이지 화면 빨개지는 기능 구현

## 코드 추가
### 탐지 코드
- PacketAnalyzer/detectors 안의 파이썬 파일, detect(packet, flow): 함수로 구현

### Streamlit 웹사이트
- PacketAnalyzer/webpages 안에서 구현
- index.py파일을 실행해서 웹서버 실행
- packets.db 파일의 내용을 기반으로 하며, 엔진과 별도 동작.
    - db 내용만 읽고 쓰고, 엔진이 어떻게 돌아가는지는 웹에서 전혀 관련 없도록.

## 그 외 다양한 모듈
- 주제나 선호에 따라 engine 폴더 안/밖에서 구동. 
- engine에 추가할 때에는 processor.run() 함수 내부에 해당 모듈 관련 코드를 추가.
- 프로젝트 루트에 폴더를 추가했을 경우 `__init__.py` 파일을 꼭 추가할 것. 

## 약속
- 작업 시작 전 develop 최신화(동기화)부터!
    ```bash
    # 동기화 방법
    
    git fetch upstream
    git merge upstream/dev
    ```
- feature 브랜치는 항상 최신 develop에서 출발
- develop 직접 커밋 금지, 모든 변경은 PR + 리뷰 1인 승인으로
- main으로 가는 PR(develop → main)은 팀장만 연다
- 궁금한 점, 결정 사항은 이 이슈 댓글로 남기기