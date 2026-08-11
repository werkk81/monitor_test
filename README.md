# monitor_test

# PyPI Anti-Malware Monitor & Evidence Collector

> **공급망 공격(Supply Chain Attack) 대응을 위한 오픈소스 패키지 실시간 정찰 및 악성 의심 근거(Evidence) 자동 수집 시스템**

본 모듈은 PyPI(Python Package Index) 저장소를 24시간 모니터링하여, 신규 등록되는 패키지 중 공급망 공격 의심 사례를 실시간으로 탐지하고 정적 분석 근거를 안전한 데이터셋(JSON) 형태로 구축하는 의존성 보안 정찰대입니다.

---

## 주요 기능 (Key Features)

1. **실시간 신규 패키지 정찰 (Real-time Feed Surveillance)**
   - PyPI RSS 피드를 지속적으로 모니터링하여 삭제(Takedown)되기 직전의 최신 배포 패키지 정보를 실시간 확보합니다.
2. **샌드박스 프리 안전 분석 (Safe Static Analysis)**
   - 의심스러운 패키지를 가상 환경에 직접 설치(`pip install`)하지 않습니다. 오직 소스 배포판(`sdist`)의 `.tar.gz` 압축파일만을 메모리 상에서 해제한 후 정적 텍스트 기반 코드를 정밀 검사하므로 감염 위험이 0%입니다.
3. **위험 행동 징후 포착 (Threat Indicator Detection)**
   - 난독화 복호화 후 즉시 실행(`exec`, `eval`), 원격 명령어 실행(`subprocess`), 악성 서버 연결 및 C2 통신(`socket`), 민감 정보 탈취용 웹훅(`discord.com/api/webhooks`) 등 해커들이 자주 사용하는 위험 시그니처 6종을 1차 스캐닝합니다. -> **단순한 정적분석**
4. **증거 기반 데이터셋 구축 (Evidence Generation & Automation)**
   - 탐지 시 "악성/정상"의 이진 분류를 넘어, **어느 파일의 몇 번째 라인에서 어떤 코드 스니펫 때문에 탐지되었는지 구체적인 근거(Evidence)**를 뽑아 JSON 형태로 구조화합니다.
   - GitHub Actions와 연동되어 매일 지정된 시간마다 자동 수집 및 안전한 데이터 커밋&푸시(GitHub 계정 제재 우회)를 수행합니다.

---

## 시스템 아키텍처 (System Architecture)

```text
[ GitHub Actions Cron 스케줄러 ] (KST 새벽 3시~8시, 10분 주기 구동)
             │
             ▼
[ PyPI 신규 패키지 RSS 감시 ] ➔ 최신 패키지 10개 추출
             │
             ▼
[ sdist 소스 아카이브 수집 ] ➔ 설치 없이 메모리 단에서 .tar.gz 다운로드
             │
             ▼
[ 1차 정적 분석 엔진 ] ➔ .py 파일 대상 Signature 패턴 1:1 대조
             │
             ├── 🟢 정상 패키지: 즉시 메모리 파기 (저장 안 함)
             └── 🔴 악성 의심: 탐지 근거(Evidence) 추출
                                     │
                                     ▼
                      [ data/detected_evidence.json ] 에 기록 누적
                                     │
                                     ▼
                      [ GitHub 저장소에 자동 Push 및 데이터셋 박제 ]
