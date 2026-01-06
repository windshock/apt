# apt (Amadey Pipeline Tools)

**위험한 악성코드 샘플/덤프를 다룹니다.**  
이 프로젝트는 **Amadey 계열 샘플 수집/다운로드/압축해제**, **Hybrid-Analysis 메모리 덤프 다운로드**, **YARA 스캔**을 반복 가능하게 수행하기 위한 도구 모음입니다.

## 안전 주의사항(필수)

- **호스트에서 직접 실행하지 말고 Docker/격리 VM에서만** 실행하세요.
- 다운로드된 샘플/덤프는 **절대 실행하지 마세요.**
- 결과/아티팩트는 Docker 볼륨(`/data`)에만 쌓이도록 구성합니다.

## 구성 파일/스크립트

- `malwarebazaar_query.py`: MalwareBazaar에서 해시 메타데이터 조회(CSV 출력)
- `malwarebazaar_download.py`: MalwareBazaar에서 샘플 다운로드 및 7z로 압축해제
- `fetch_memory_dump.sh`: Hybrid-Analysis에서 샘플의 메모리 덤프 ZIP 다운로드
- `scripts/yara_eval.py`: 로컬 디렉터리(YARA 대상)에 대해 YARA 스캔 + CSV 리포트
- `scripts/apt_docker.sh`: 모든 명령을 Docker 컨테이너 안에서 실행하는 래퍼
- `scripts/apt_shell.sh`: 컨테이너 쉘 진입

## 환경변수(.env)

`.env`는 **커밋 금지**입니다(예: `.gitignore`).

우선 `env.example`을 복사해서 채우세요:

```bash
cp env.example .env
```

주요 값:

- **`MB_API_KEY`**: MalwareBazaar API Key
- **`MB_ZIP_PASSWORD`**: MalwareBazaar 샘플 ZIP 비밀번호(기본 `infected`)
- **`HA_COOKIE`**: Hybrid-Analysis 로그인 세션 쿠키(브라우저에서 복사)

옵션(다운로드 과다로 끊김/차단 방지):

- **`MB_SLEEP_MIN`, `MB_SLEEP_MAX`**: 샘플 간 랜덤 딜레이(초)
- **`MB_RETRY_MAX`, `MB_RETRY_BASE_SLEEP`, `MB_RETRY_MAX_SLEEP`**: 재시도/백오프
- **`MB_TIMEOUT`**: 요청 타임아웃(초)

## Docker 실행(권장)

빌드:

```bash
docker compose build
```

컨테이너 쉘:

```bash
bash scripts/apt_shell.sh
```

Docker에서 명령 실행:

```bash
bash scripts/apt_docker.sh python3 malwarebazaar_query.py -h
bash scripts/apt_docker.sh python3 malwarebazaar_download.py -h
bash scripts/apt_docker.sh bash fetch_memory_dump.sh -h || true
bash scripts/apt_docker.sh yara --version
```

> 모든 아티팩트는 기본적으로 Docker 볼륨의 `/data` 아래에 저장됩니다.

## 기본 워크플로우(다운로드 → 검사)

### 1) 해시 목록 준비

이미 해시 목록이 있다면(예: `/data/amadey_100_hashes.txt`) 그대로 사용하면 됩니다.

호스트 파일을 Docker로 읽고 싶으면, `/work`는 read-only 마운트이므로 **입력 파일을 `/data`로 복사**해두는 방식이 가장 단순합니다:

```bash
# 예: 호스트의 amadey_mb_100_hashes.txt 를 /data 로 복사
docker compose run --rm apt bash -lc "cp /work/amadey_mb_100_hashes.txt /data/amadey_100_hashes.txt"
```

### 2) MalwareBazaar 샘플 다운로드(+압축해제)

```bash
bash scripts/apt_docker.sh python3 malwarebazaar_download.py \
  --file /data/amadey_100_hashes.txt \
  --limit 100 \
  --verbose
```

출력(기본):
- 다운로드 ZIP: `/data/download/`
- 압축해제 결과: `/data/unzip/`

### 3) YARA 스캔(다운로드 샘플 대상)

```bash
bash scripts/apt_docker.sh python3 scripts/yara_eval.py \
  --rules /work/win.amadey_auto.yar \
  --target /data/unzip \
  --out /data/yara_eval_downloaded.csv
```

### 4) (선택) Hybrid-Analysis 메모리 덤프 다운로드

`HA_COOKIE`가 필요합니다.

```bash
bash scripts/apt_docker.sh bash fetch_memory_dump.sh \
  --sha256-list /data/amadey_100_hashes.txt \
  --out-dir /data/ha_dumps \
  --max-samples 100 \
  --max-dumps 2
```

네트워크/TLS 오류나 차단이 의심되면(예: `curl: (35) TLS connect error`, `Could not connect to server`) 아래 값을 `.env`에서 늘려서 더 천천히/재시도 하세요:

```bash
HA_SLEEP_MIN=4
HA_SLEEP_MAX=10
HA_RETRY_MAX=8
```

### 5) (선택) 메모리 덤프도 YARA 스캔

`/data/ha_dumps`에는 **ZIP이 그대로 저장**됩니다. YARA는 ZIP 내부를 자동으로 풀어서 스캔하지 않으므로, **먼저 압축해제 후(`/data/ha_dumps_unz`) 그 디렉터리를 스캔**해야 합니다.

압축해제:

```bash
bash scripts/apt_docker.sh bash -lc '
set -e
mkdir -p /data/ha_dumps_unz
for z in /data/ha_dumps/*.zip; do
  d="/data/ha_dumps_unz/$(basename "$z" .zip)"
  mkdir -p "$d"
  unzip -o -q "$z" -d "$d" || true
done
'
```

압축해제된 파일(예: `*.mdmp`) 대상으로 스캔:

```bash
bash scripts/apt_docker.sh python3 scripts/yara_eval.py \
  --rules /work/win.amadey_auto.yar \
  --target /data/ha_dumps_unz \
  --out /data/yara_eval_memory_unz.csv
```

## 문제 해결(Troubleshooting)

- **다운로드가 끊김/차단되는 느낌**: `.env`에서 `MB_SLEEP_*`를 늘리고 `MB_RETRY_*`를 키우세요.
- **HA 메모리덤프가 HTML로 내려옴**: 보통 쿠키 만료/권한 문제입니다. `HA_COOKIE`를 갱신하세요.
- **호스트 백신 충돌**: 호스트 디렉터리(`.`)에 샘플이 떨어지지 않게 하고 `/data` 볼륨만 사용하세요.


