# 격리 이후 자동 메모리 분석 워크플로우
## (Automated Post-Isolation Memory Analysis Workflow)

---

## 0. 목표 및 설계 원칙

Cybereason에서 탐지 및 **격리(Isolation)** 된 엔드포인트를 대상으로,  
**격리 이후 자동으로 메모리 기반 분석을 수행**하는 IR(Incident Response) 자동화 시스템을 구현한다.

### 핵심 목표
- 격리된 상태에서만 메모리 접근 및 분석 수행
- 서버 중심 분석(MemProcFS) + 엔드포인트 최소 개입
- YARA 기반 메모리 위협 탐지의 자동화
- 벤더 종속 최소화 (EDR 교체 가능)

### 설계 원칙
- Cybereason은 **탐지/격리/컨텍스트 제공(Syslog/API)** 까지만 담당
- IR 체인은 **EDR 내부 API에 직접 의존하지 않음**
- 엔드포인트는 평소 휴면, **격리 시 원샷 실행 후 self-disable**
- 자동화는 **High / Mid YARA 룰만** 대상

---

## 1. 전체 아키텍처 구성 요소

### 1.1 Cybereason Management Console (On-Prem)
- 모든 PC Agent 텔레메트리 수신
- Malop 생성 및 Severity 판단
- Endpoint Isolation 수행
- **Syslog(CEF) / REST API 제공 (외부 연계 유일 지점)**

---

### 1.2 IR Orchestrator (서버, 상시 실행)

역할:
- Cybereason Syslog(CEF) 수신 또는 API 폴링
- 사건(Case) 생성 및 상태 관리 (idempotent)
- IR Agent의 Join 요청 수신 및 승인
- Work Order 생성/전달
- IR Worker 실행 제어
- 결과/증거 수집 및 보관

필수 기능:
- REST API (IR Agent ↔ Orchestrator)
- Case State DB (SQLite → Postgres/Redis)
- Evidence Storage (Local FS / MinIO / S3)
- Audit Log / Metrics

---

### 1.3 IR Worker (서버, 컨테이너/프로세스)

역할:
- MemProcFS 실행
- LeechAgent(엔드포인트)에 연결
- 메모리 스캔 및 YARA 실행
- 조건부 덤프 생성
- 결과 JSON 및 증거 업로드

구현:
- Docker 컨테이너 권장
- Case 단위 실행 후 종료

---

### 1.4 IR Agent (엔드포인트, 사전 설치)

역할:
- **격리 여부를 자가 판단**
- 격리 확인 시:
  - LeechAgent 실행
  - IR Orchestrator에 Join
  - Work Order 수신
- 작업 완료 후:
  - LeechAgent 종료
  - self-disable 또는 sleep 복귀

조건:
- Windows 기준 SYSTEM 권한
- 평상시 리소스 사용 최소

---

### 1.5 LeechAgent (엔드포인트)
- MemProcFS의 메모리 접근 백엔드
- IR Agent에 의해 **필요 시점에만 실행**

---

## 2. 트리거 및 사건 흐름

### 2.1 이벤트 트리거 (Cybereason → IR Orchestrator)

입력:
- Syslog(CEF) 또는 API

필수 필드:
- event_time
- endpoint_id / hostname
- malop_id
- severity
- detection_type
- isolation_status (가능 시)

Case Key:
```

case_key = endpoint_id + malop_id

````

- 동일 case_key는 **중복 생성 금지 (idempotent)**

---

### 2.2 격리 여부 판단 (IR Agent)

IR Agent는 Cybereason API에 직접 질의하지 않는다.

#### 기본 판단 로직 (필수)
- 네트워크 상태 기반 AND 조건:
  - IR 서버(관리망) 접근 가능
  - 외부 인터넷 접근 불가

#### 보조 신호 (옵션)
- Cybereason Agent 서비스 실행 여부
- 로컬 방화벽 정책 변화

격리 확인 시에만 다음 단계 진행.

---

## 3. 메모리 분석 스코프 전략 (A + C 혼합)

본 시스템은 **A + C 혼합 전략**을 기본으로 한다.

### C. 기본 전략 (필수): 구조 기반 제한 스캔
Cybereason 컨텍스트가 없어도 항상 동작해야 한다.

스캔 제한 기준(설정 가능):
- RWX 또는 실행 가능한 VAD
- Private VAD 우선
- 언링크/비정상 PE 모듈
- 비정상 메모리 보호 플래그

---

### A. 향상 전략 (옵션): Cybereason API 기반 타깃 PID
가능한 경우, Orchestrator는 Cybereason API를 통해 Malop 상세를 조회하여:
- 의심 PID
- 프로세스 트리
- 이미지 경로/해시
를 수집한다.

- 수집된 PID는 `work_order.target_pids`로 전달
- Worker는 해당 PID만 **우선 스캔**

#### 폴백
- API 실패/지연/권한 부족 시
- 자동으로 **C 전략**으로 전환

---

### Work Order 필드
```json
{
  "case_id": "...",
  "target_pids": [1234, 5678],   // optional
  "scope_policy": "vad_rwx_private",
  "yara_levels": ["HIGH", "MID"],
  "dump_policy": "HIGH_ONLY"
}
````

우선순위:

1. target_pids 존재 → 정밀 스캔
2. 없으면 scope_policy 기반 구조 스캔

---

## 4. YARA 룰 레벨 정의 및 자동화 정책

### YARA 분류 기준 (YARAify YARAhub)

분류는 `meta.description` 및 `meta` 태그(`family`, `tags`) 기반.

#### High (상)

* loader / packer / obfuscation
* memory behavior 신호

#### Mid (중)

* attack-chain / framework
* campaign / tooling

#### Low (하)

* family / identity indicator
* **family 태그가 있으면 무조건 Low**

---

### 자동 실행 정책

* 자동 실행: **High + Mid**
* 자동 제외: **Low**

Low 룰은 FP 및 정책 리스크로 인해:

* 자동화에서 제외
* 수동/사후 분석 전용

---

## 5. 덤프 정책 (기본)

* High hit:

  * 프로세스 덤프 (필수)
  * 물리 덤프 (옵션)
* Mid hit:

  * 프로세스 덤프 (정책에 따라)
* No hit:

  * 덤프 없음
  * 메타데이터/구조 지표만 저장

### 5.1 (추천) Full dump 승격 규칙 (운영형)

YaraHub(Yaraify) 룰셋은 High/Mid가 “태깅” 성격으로 동시에 발생할 수 있으므로,
`HIGH>=1 AND MID>=1` 만으로 무조건 물리덤프(Full dump) 승격을 하면 **덤프 폭주** 위험이 있다.

따라서 Full dump는 아래 조건 중 하나를 만족할 때만 수행한다:

- **Rule-count gate**: `HIGH >= 2 AND MID >= 1` 이면 Full dump
- **Strong-High gate**: `STRONG_HIGH >= 1 AND MID >= 1` 이면 Full dump

여기서 `STRONG_HIGH`는 “범용/구조 지표” 성격의 High 룰을 제외한 High 룰을 의미한다.
예(기본 제외 후보):
- `meth_*`, `pe_*`
- `DetectEncryptedVariants`
- `Sus_CMD_Powershell_Usage`

추가 규칙:
- `HIGH + MID + LOW` 조합은 **자동 Full dump 승격 조건으로 사용하지 않는다.**
  - Low는 family/identity indicator 성격으로 FP/정책 리스크가 있으므로,
    자동화에서는 “우선순위/분류” 신호로만 사용한다.

모든 산출물:

* SHA-256 해시
* 생성 시각 기록

---

## 6. 증거 관리 (Evidence)

* 결과 JSON, 로그, 덤프 파일 저장

* `manifest.json` 생성:

  * 파일 목록
  * 해시
  * 생성 시각
  * endpoint_id / case_id

* 저장소:

  * Local FS / MinIO / S3 호환

---

## 7. 보안 요구사항

* IR Agent / LeechAgent 무결성 검증(해시/서명)
* TLS 필수 (Agent ↔ Server)
* 격리 예외는 IR 서버만 허용
* 덤프 파일 at-rest 암호화
* 모든 단계 Audit Log 기록

### 7.1 (권장) mTLS Enrollment (CSR 기반)

운영에서는 shared-key 대신 **mTLS(클라이언트 인증서)** 를 권장한다.
이때 서버가 개인키를 생성/배포하면 유출 리스크가 커지므로, 아래 흐름을 사용한다:

1) **Agent 로컬에서 키페어 생성**
2) Agent가 CSR(Certificate Signing Request)을 생성하여 Orchestrator(또는 CA 서비스)에 제출
3) 서버는 CSR을 검증 후 **서명된 클라이언트 인증서만** 발급(개인키는 절대 서버로 보내지 않음)

부트스트랩 인증(예):
- 사내 PKI/AD 기기 인증서 기반 1차 인증
- 설치 시 1회성 Enrollment Token

---

## 15. (결정) LeechAgent 연결 정책 (권장)

- Worker(DFIR 서버, Linux) ↔ Endpoint(Windows LeechAgent) 연결은 **gRPC / TCP 28474** 사용
- 방화벽 예외(격리 예외):
  - **DFIR 서버 → 격리 PC: 28474/TCP 허용**
  - Agent ↔ Orchestrator는 `dfir.skplanet.com:443` (mTLS 권장)

### 15.2 (운영 참고) 시간 동기화 / keepalive 제약

- **Windows 시간 동기화(NTP) 필수**
  - 시간이 틀리면 gRPC mTLS에서 인증서 유효기간(`notBefore/notAfter`) 검증으로 실패할 수 있음.
- **LeechAgent client keepalive timeout(약 75초)**
  - upstream LeechAgent는 client keepalive 타임아웃(예: `75*1000ms`)이 코드 레벨로 존재함.
  - Worker는 장시간 처리 중 유휴로 끊기지 않도록 MemProcFS 마운트에 주기적으로 접근(keepalive)한다.
  - 기본값: `WorkOrder.memprocfs.keepalive_interval_seconds = 20` (75초보다 충분히 짧게)

### 15.1 개발/PoC 전제: Windows 테스트 엔드포인트 필요 시점

서버 측(Orchestrator/Worker) 개발은 Linux만으로도 계속 진행 가능하지만,
아래 항목을 “끝까지(End-to-End)” 검증하려면 **Windows PC 또는 Windows VM 1대**가 필요하다:

- Windows에서 LeechAgent 실행/권한/드라이버가 정상 동작
- DFIR 서버 → Windows: `28474/TCP` 네트워크 예외가 실제로 적용됨
- MemProcFS가 LeechAgent를 통해 원격 메모리 접근 성공
- 덤프 생성(프로세스/물리) 및 Evidence 업로드 성공, 소요시간/용량 계측

---

## 8. 운영/관측

로그:

* Case lifecycle
* Agent join/실패
* MemProcFS 연결
* YARA 실행 결과
* 덤프/업로드 상태

메트릭:

* Case 처리 시간
* 실패율(stage별)
* 덤프 용량

대시보드(권장):

* Orchestrator는 **Dashboard(UI)** 를 제공하여, 현재 분석 중/완료/실패 케이스의 상태를 한 눈에 볼 수 있어야 한다.
  * 표시 항목(최소): case_id, endpoint_id/hostname, status, updated_at, (가능하면) High/Mid/Low 히트 카운트, 결과 업로드 시각
  * 보호: 운영에서는 mTLS를 우선하고, UI 자체도 별도 인증(예: Basic/SSO)으로 보호

---

## 9. 배포 요구사항

* Server:

  * Docker Compose 또는 Kubernetes
* Worker:

  * 컨테이너 이미지
* Endpoint:

  * IR Agent 사전 설치
  * LeechAgent/드라이버 사전 배포
  * 기본 비활성 상태 유지

---

## 10. 성공 기준 (Acceptance)

* 격리 상태에서만 실행됨
* High/Mid 룰만 자동 실행
* PID 제공 시 정밀 스캔, 없으면 폴백 정상 동작
* 중복 이벤트에도 case 폭주 없음
* 작업 후 엔드포인트 self-disable 복귀

---

## 11. (구현) 레포 구조 / 모듈 경계 (MVP)

본 레포(`apt`)는 기존 “샘플/덤프 수집+YARA 실험 도구”를 유지하면서, 본 문서의 IR 체인을 `ir/` 모듈로 **분리 구현**한다.

```
ir/
  common/        # 공통 스키마(WorkOrder/Result/Manifest) + 서명 유틸
  orchestrator/  # REST API + SQLite(case state) + evidence 저장
  worker/        # case 단위 실행(컨테이너/프로세스) → 스캔 → 업로드
  agent/         # 엔드포인트 stub(격리 자가판단/Join/LeechAgent 실행 훅)
docker-compose.ir.yml
```

- 기존 `docker-compose.yml`은 그대로 두고, IR 전용은 `docker-compose.ir.yml`로 별도 제공한다.

---

## 12. (구현) Orchestrator API 스펙 (MVP)

### 12.1 인증 (MVP)

- 모든 요청에 `X-IR-Key: <shared>` 헤더 필수 (`IR_SHARED_KEY`).
- 옵션: `IR_REQUIRE_SIGNATURE=1`이면 HMAC 서명 필수
  - `X-IR-Timestamp`: epoch seconds
  - `X-IR-Signature`: `HMAC-SHA256(key, "<ts>\\n<method>\\n<path>\\n<sha256(body)>")`

> 운영에서는 mTLS를 권장하며, 본 MVP는 최소한의 shared-key(+선택적 서명)만 포함한다.

### 12.2 엔드포인트

- `GET /healthz`: 헬스체크
- `POST /v1/events/cybereason`: Cybereason(Syslog/API) 이벤트 입력 → `case_key = endpoint_id:malop_id` 기준 멱등 case 생성
- `POST /v1/agents/join`: Agent join/upsert + 해당 endpoint의 active case에 attach
- `GET /v1/agents/{agent_id}/work-orders/next`: WorkOrder 발급/재발급
- `POST /v1/cases/{case_id}/results`: Worker 결과 업로드(케이스 완료 처리)
- `POST /v1/cases/{case_id}/manifest`: 산출물 목록/해시 업로드
- `POST /v1/cases/{case_id}/evidence`: 증거 파일 업로드(multipart)

---

## 13. (구현) Evidence 저장 레이아웃 (NAS/로컬 공통)

Orchestrator는 `IR_EVIDENCE_DIR` 아래에 케이스 단위로 저장한다(=NAS 마운트 가능):

```
<IR_EVIDENCE_DIR>/
  <case_id>/
    result.json
    manifest.json
    files/
      <uploaded_file_1>
      <uploaded_file_2>
```

추가 확장(권장):
- `audit/`(감사 로그)
- `dumps/`(덤프 산출물)
- `logs/`(worker/agent 로그)

---

## 14. (구현) YARA High/Mid 자동화 반영

- YaraHub(Yaraify) 룰을 High/Mid/Low로 분류한 기준은 `yaraify_rules_classification.md`를 단일 소스로 사용한다.
- `scripts/yaraify_buckets_from_md.py`로 `buckets.json(high/mid/low)`을 생성하여 Worker가 룰 레벨을 결정한다.
- 자동 실행 대상: **High + Mid**만.

---
