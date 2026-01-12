# apt (Amadey Pipeline Tools)

**위험한 악성코드 샘플/덤프를 다룹니다.**  
이 프로젝트는 **Amadey 계열 샘플 수집/다운로드/압축해제**, **Hybrid-Analysis 메모리 덤프 다운로드**, **YARA 스캔**을 반복 가능하게 수행하기 위한 도구 모음입니다.

## 안전 주의사항(필수)

- **호스트에서 직접 실행하지 말고 Docker/격리 VM에서만** 실행하세요.
- 다운로드된 샘플/덤프는 **절대 실행하지 마세요.**
- 결과/아티팩트는 Docker 볼륨(`/data`)에만 쌓이도록 구성합니다.

## IR (격리 이후 자동 메모리 분석 워크플로우) - MVP

이 레포는 기존 `apt`(샘플/덤프 수집·YARA 실험) 외에,
`격리_이후_자동_메모리_분석_워크플로우_개발요구사항.md` 기반의 **IR Orchestrator/Worker/Agent 스캐폴딩**을 `ir/`에 포함합니다.

- 실행: `docker compose -f docker-compose.ir.yml up`
- 가이드: `ir/README.md`

## 구성 파일/스크립트

- `malwarebazaar_hunt.py`: MalwareBazaar에서 태그 기준으로 해시 목록(예: Amadey 100개) 생성
- `malwarebazaar_query.py`: MalwareBazaar에서 해시 메타데이터 조회(CSV 출력)
- `malwarebazaar_download.py`: MalwareBazaar에서 샘플 다운로드 및 7z로 압축해제
- `fetch_memory_dump.sh`: Hybrid-Analysis에서 샘플의 메모리 덤프 ZIP 다운로드
- `scripts/yara_eval.py`: 로컬 디렉터리(YARA 대상)에 대해 YARA 스캔 + CSV 리포트
- `scripts/yara_rule_stats.py`: YARA 출력(룰명/파일경로)을 룰별 통계 CSV로 집계
- `scripts/yara_folder_coverage.py`: YARA 출력(룰명/파일경로)을 폴더 단위(폴더 내 1개라도 매치면 탐지)로 집계
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

없다면, MalwareBazaar에서 **Amadey 태그 기준으로 100개 해시를 생성**할 수 있습니다:

```bash
bash scripts/apt_docker.sh python3 malwarebazaar_hunt.py --tag amadey --limit 100
```

기본 출력:
- 해시 목록: `/data/amadey_100_hashes.txt`
- 메타 CSV: `/data/amadey_100_meta.csv`

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

일부 샘플은 내부가 다시 `.zip/.7z/.rar`로 **중첩 압축**되어 있을 수 있습니다. 이 경우 YARA 커버리지를 올리려면 중첩 압축까지 자동으로 풀어주세요:

```bash
bash scripts/apt_docker.sh python3 malwarebazaar_download.py \
  --file /data/amadey_100_hashes.txt \
  --limit 100 \
  --recursive-extract \
  --verbose
```

중첩 압축 해제 결과는 `UNZIP_DIR/_nested/` 아래에 생성됩니다(예: `/data/unzip_amd_100/_nested/...`).

`--file/--limit`로 “이번에 처리할 샘플”이 정해져 있다면, **런별로 디렉터리를 분리**해두면(누적 방지) 스캔도 해당 폴더만 하면 됩니다:

```bash
MB_DOWNLOAD_DIR=/data/download_amd_100 \
MB_UNZIP_DIR=/data/unzip_amd_100 \
bash scripts/apt_docker.sh python3 malwarebazaar_download.py \
  --file /data/amadey_100_hashes.txt \
  --limit 100 \
  --verbose
```

### 3) YARA 스캔(다운로드 샘플 대상)

```bash
bash scripts/apt_docker.sh python3 scripts/yara_eval.py \
  --rules /work/win.amadey_auto.yar \
  --target /data/unzip_amd_100 \
  --out /data/yara_eval_downloaded.csv
```

특정 파일만(다운로드/추출 결과 중 일부만) 스캔하고 싶으면, 스캔 대상 파일 경로 목록을 만들어 `--scan-list`로 전달하면 됩니다:

```bash
# 예: /data/unzip 아래 파일들 중 원하는 것만 골라 목록 생성
find /data/unzip -type f | head -100 > /data/scan_list.txt

bash scripts/apt_docker.sh python3 scripts/yara_eval.py \
  --rules /work/win.amadey_auto.yar \
  --target /data/unzip \
  --scan-list /data/scan_list.txt \
  --out /data/yara_eval_downloaded_subset.csv
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

## Yaraify(YaraHub) 룰셋으로 스캔/통계(권장)

Yaraify YaraHub 룰셋 ZIP: `https://yaraify.abuse.ch/yarahub/yaraify-rules.zip`

Docker에서 다운로드 + 컴파일(`yarac`) 후 스캔:

```bash
bash scripts/apt_docker.sh bash -lc '
set -e
mkdir -p /data/yaraify/rules /data/yaraify/out
cd /data/yaraify
curl -fsSL -L -o yaraify-rules.zip "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"
unzip -q -o yaraify-rules.zip -d rules

# NOTE: 일부 룰 파일은 문법/식별자 문제로 컴파일이 실패할 수 있습니다.
# yarac 에러에 찍히는 파일을 제거하고 다시 시도하세요.
yarac $(find rules -type f -name "*.yar" -o -name "*.yara" | tr "\n" " ") /data/yaraify/yarahub.compiled

yara -C -r -p 4 -a 30 /data/yaraify/yarahub.compiled /data/unzip_amd_100 > /data/yaraify/out/scan_unzip_amd_100.txt || true
'
```

룰별 “몇 개 파일에서 매치됐는지” 통계:

```bash
bash scripts/apt_docker.sh python3 scripts/yara_rule_stats.py \
  --in /data/yaraify/out/scan_unzip_amd_100.txt \
  --out /data/yaraify/out/stats_rules_unzip_amd_100.csv
```

HA 메모리 덤프(`mdmp`)는 폴더별로 1개라도 매치되면 “탐지”로 보려면:

```bash
# 스캔
bash scripts/apt_docker.sh bash -lc '
yara -C -r -p 4 -a 30 /data/yaraify/yarahub.compiled /data/ha_dumps_unz > /data/yaraify/out/scan_ha_dumps_unz_mdmp.txt || true
'

# 폴더 커버리지 집계
bash scripts/apt_docker.sh python3 scripts/yara_folder_coverage.py \
  --in /data/yaraify/out/scan_ha_dumps_unz_mdmp.txt \
  --root /data/ha_dumps_unz \
  --out /data/yaraify/out/stats_ha_dumps_unz_folder_coverage.csv \
  --print-undetected
```

### (예시) “최소 룰 조합으로 최고 탐지율” 찾기

아래는 **이 프로젝트에서 실제로 돌린 한 번의 실험 결과 예시**입니다. 데이터셋/집계 기준이 바뀌면 숫자는 달라질 수 있습니다.

- **HA 메모리 덤프(폴더 기준)**: `/data/ha_dumps_unz/<dump_folder>/...*.mdmp` 에서 **폴더 안에 1개라도 매치가 있으면 탐지로 카운트**
  - 결과: **60/63 폴더 탐지(95.24%)**
  - **최소 룰 조합(최고치 달성)**:
    - `DetectEncryptedVariants`
    - `meth_get_eip`

- **다운로드 샘플(sha 기준)**: `/data/unzip_amd_100`의 top-level `exe/zip/ps1/hta` + `_nested` 내부 파일(아카이브 컨테이너 제외) 중 **어느 하나라도 매치가 있으면 해당 sha를 탐지로 카운트**
  - 결과: **71/100 sha 탐지(71.0%)**
  - **최소 룰 조합(최고치 달성)**:
    - `golang_bin_JCorn_CSC846`
    - `Sus_CMD_Powershell_Usage`
    - `pe_detect_tls_callbacks`
    - `detect_Redline_Stealer`
    - `pe_no_import_table`

### YaraHub 결과를 “탐지율”이 아니라 “프로파일(상/중/하)”로 읽기

YaraHub(=Yaraify) 룰은 **샘플 패밀리 확증용**이라기보다, HA region/실행 메모리를 **성격(행위/구조)으로 태깅**하는 데에 유용합니다.

- **상(High, Memory-centric 신호)**: 로더/언패커/침투형 메모리에서 흔한 generic 신호  
  예: `meth_get_eip`, `pe_detect_tls_callbacks`, `pe_no_import_table`, `Sus_CMD_Powershell_Usage`, `golang_bin_JCorn_CSC846`, `DetectEncryptedVariants`
- **중(Mid, 프레임워크/캠페인 흔적)**: 공격 체인/툴 흔적(예: Cobalt Strike) 또는 과잉 태그 가능성이 있는 행위 카테고리  
  예: `cobalt_strike_tmp01925d3f`, `RANSOMWARE`, `ScanStringsInsocks5systemz`
- **하(Low, 패밀리 단서)**: 특정 패밀리/스틸러 계열 등 “확증(어트리뷰션 힌트)”에 가까운 룰  
  예: `StealcV2`, `aachum_Stealcv2`, `win_lumma_generic`

중요:
- **Low는 ‘자동 대응 트리거’가 아니라, 분석가가 최종 라벨링/우선순위에 참고하는 단서**로 쓰는 것을 권장합니다.
  - 이유: 패밀리/아이덴티티 룰은 종종 문자열/부분 패턴 기반이라 **환경/코퍼스에 따라 FP가 생길 수 있고**, 자동화 액션(덤프/격리/티켓)과 결합되면 운영 리스크가 커질 수 있습니다.
  - 따라서 본 프로젝트의 IR 자동화 기본 정책은 **High+Mid만 자동 실행/판단에 사용**하고, Low는 결과에 **태그로만 포함**합니다.

핵심은:
- **상/중은 “이 메모리가 어떤 성격인가”를 설명하는 태그**로 사용
- **패밀리 확증은 하위권 룰(Malpedia/전용 룰 포함)로만** 판단

#### SHA256 기준으로 프로파일 합치기(권장)

HA `mdmp_extracted`의 `dump_folder`는 보통 `<sha256>_<dumpid>_memory` 형태이므로, **`dumpid` 단위가 아니라 sha256 단위로 묶어서** 상/중/하 조합을 보길 권장합니다.

이를 위해 `scripts/yara_folder_profile.py`를 사용합니다:

```bash
# (1) 먼저, 스캔 결과에 실제로 등장한 룰들로 “버킷 템플릿(JSON)” 생성
bash scripts/apt_docker.sh bash -lc '
base=/data/scan_all_rulesets/<timestamp>
python3 /work/scripts/yara_folder_profile.py \
  --in "$base/scans/yarahub.txt" \
  --root /data/mdmp_extracted \
  --out /tmp/out.csv \
  --write-buckets-template "$base/yarahub_buckets.json"
'

# (2) $base/yarahub_buckets.json 을 열어서 high/mid/low에 룰을 재분류

# (3) sha256 기준으로 high+mid+low 모두 포함한 그룹 찾기
bash scripts/apt_docker.sh bash -lc '
base=/data/scan_all_rulesets/<timestamp>
python3 /work/scripts/yara_folder_profile.py \
  --in "$base/scans/yarahub.txt" \
  --root /data/mdmp_extracted \
  --out "$base/yarahub_sha256_profile.csv" \
  --group sha256 \
  --buckets "$base/yarahub_buckets.json" \
  --print-all3
'
```

#### (권장) `yaraify_rules_classification.md`를 단일 소스로 써서 buckets 자동 생성

레포의 `yaraify_rules_classification.md`는 YaraHub 룰을 High/Mid/Low로 분류한 “사람이 읽는 기준”입니다.  
이를 그대로 `buckets.json`으로 변환하려면 아래 스크립트를 사용하세요:

```bash
# md -> buckets json
bash scripts/apt_docker.sh python3 scripts/yaraify_buckets_from_md.py \
  --in /work/yaraify_rules_classification.md \
  --out /data/yaraify/yarahub_buckets.json

# sha256 기준으로 high+mid+low 조합 계산
bash scripts/apt_docker.sh python3 scripts/yara_folder_profile.py \
  --in /data/yaraify/out/scan_ha_dumps_unz_mdmp.txt \
  --root /data/mdmp_extracted \
  --group sha256 \
  --buckets /data/yaraify/yarahub_buckets.json \
  --out /data/yaraify/out/yarahub_sha256_profile.csv \
  --print-all3
```

## YARA-Signator로 HA mdmp 기반 룰 생성(고급)

YARA-Signator는 **PostgreSQL + capstone_server + SMDA 리포트**를 요구하는 무거운 파이프라인입니다. (요약/전제는 upstream 문서 참고)

이 프로젝트는 이를 Docker로 돌릴 수 있도록 `signator_stack/`(compose)와 `scripts/signator_prepare_ha_mdmp.py`(SMDA 리포트 생성)를 제공합니다.

### 1) 준비: mdmp → curated repo + SMDA reports

```bash
# (예시) HA mdmp 폴더 5개, 폴더당 mdmp 10개만 샘플링해서 준비
bash scripts/apt_docker.sh python3 scripts/signator_prepare_ha_mdmp.py \
  --src /data/ha_dumps_unz \
  --datastore /data \
  --family win.amadey \
  --max-folders 5 \
  --max-files-per-folder 10
```

생성되는 경로(도커 볼륨 /data):
- curated repo: `/data/malpedia/win.amadey/ha_mdmp/...`
- smda reports: `/data/smda_report_output/*.smda`
- signator output: `/data/yara-output/` (signator 실행 후 생성)

### 2) 실행: signator stack

```bash
docker compose -f signator_stack/docker-compose.yml up --build
```

완료되면 `/data/yara-output/` 아래에 생성된 룰/리포트를 확인하세요.

## mdmp는 “전체 스캔” 대신 이렇게 쪼개서 스캔하기 (권장)

Hybrid-Analysis에서 내려받은 “memory dumps”는 보통 `/data/ha_dumps_unz/<dump_folder>/*.mdmp` 형태로 풀리는데,
여기서 `*.mdmp`는 **Windows Minidump 포맷(‘MDMP’)** 이 아니라 **이미 ‘메모리 region 단위로 쪼개진 raw bytes’** 인 경우가 많습니다.
이 경우 Volatility로 “모듈/VAD”를 다시 추출하는 것이 아니라, 아래처럼 **고신호(high-signal) region만 선택해서 YARA로 스캔**하는 게 빠르고 안정적입니다.

- **로드된 PE 모듈(프록시)**: region이 `MZ`로 시작하고 `PE\0\0` 시그니처가 유효한 경우 (PE header region)
- **Executable/RWX region**: 파일명 끝의 `.<8hex>.mdmp` 값이 Windows `PAGE_EXECUTE*` 보호(예: `0x20`, `0x40`)로 해석되는 경우

이 프로젝트는 위 선택을 `/data`로 뽑는 래퍼를 제공합니다: `scripts/extract_mdmp.sh`

### 1) HA region-split mdmp에서 “선택 추출”하기

```bash
# /data/ha_dumps_unz 아래의 각 <dump_folder>/ 를 처리해서
# /data/mdmp_extracted/<dump_folder>/{dlllist,malfind}/ 로 심볼릭링크를 생성
bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh \
  --mdmp /data/ha_dumps_unz

# RWX(0x40)만 보고 싶으면
bash scripts/apt_docker.sh bash scripts/extract_mdmp.sh \
  --mdmp /data/ha_dumps_unz \
  --rwx-only
```

결과:
- `/data/mdmp_extracted/<dump_folder>/dlllist/` : PE header region (모듈 후보)
- `/data/mdmp_extracted/<dump_folder>/malfind/` : executable/RWX region (주입/쉘코드 후보)

### 2) 선택 추출물에 대해 `win.amadey.yar` 스캔하기

```bash
bash scripts/apt_docker.sh python3 scripts/yara_eval.py \
  --rules /data/rules/malpedia/win.amadey.yar \
  --target /data/mdmp_extracted \
  --out /data/yara_eval_mdmp_extracted_win.amadey.csv
```

## (고급) Volatility3 + YARA 스캔 (`--plugin-dirs`, windows.yarascan)

Volatility2에서 흔히 보던 `windows.yarascan` 워크플로우를 Volatility3에서 쓰려면, **python YARA 바인딩(yara-python)** 이 필요합니다.
이 프로젝트는 Docker 이미지에 `yara-python`을 포함했고, `vol_plugins/windows/yarascan.py`로 **Volatility3의 `windows.vadyarascan`을 `windows.yarascan` 이름으로 alias** 해두었습니다.

> 주의: 이 방식은 **Volatility3가 스택(커널 레이어/심볼) 구성이 가능한 “진짜 메모리 이미지(raw/vmem 등)”** 에서만 동작합니다.  
> Hybrid-Analysis `ha_dumps_unz`의 region-split `*.mdmp`에는 적용하기 어렵고, 그 경우는 위의 `/data/mdmp_extracted` 방식이 권장입니다.

```bash
# (예시) Volatility3 built-in: windows.vadyarascan
bash scripts/apt_docker.sh vol -f /data/memory.raw \
  windows.vadyarascan --yara-file /data/rules/malpedia/win.amadey.yar --pid 1234

# (예시) 외부 플러그인(alias) 로드: windows.yarascan (== windows.vadyarascan)
bash scripts/apt_docker.sh vol --plugin-dirs /work/vol_plugins -f /data/memory.raw \
  windows.yarascan --yara-file /data/rules/malpedia/win.amadey.yar --pid 1234

# 래퍼 스크립트 사용
bash scripts/apt_docker.sh bash scripts/vol_yarascan.sh \
  --mem /data/memory.raw \
  --rules /data/rules/malpedia/win.amadey.yar \
  --pid 1234
```

## 문제 해결(Troubleshooting)

- **다운로드가 끊김/차단되는 느낌**: `.env`에서 `MB_SLEEP_*`를 늘리고 `MB_RETRY_*`를 키우세요.
- **HA 메모리덤프가 HTML로 내려옴**: 보통 쿠키 만료/권한 문제입니다. `HA_COOKIE`를 갱신하세요.
- **호스트 백신 충돌**: 호스트 디렉터리(`.`)에 샘플이 떨어지지 않게 하고 `/data` 볼륨만 사용하세요.

## (옵션) THOR Lite로 스캔하기

THOR Lite는 Nextron Systems의 무료 IOC/YARA 스캐너입니다. ([THOR Lite 다운로드/라이선스 안내](https://www.nextron-systems.com/thor-lite/))

이 프로젝트는 **바이너리를 레포에 포함(커밋)하지 않고**, Docker 볼륨(`/data`)에 둔 THOR Lite를 실행할 수 있게 래퍼만 제공합니다.

### 1) THOR Lite 준비 (/data)

- THOR Lite를 다운로드/압축 해제 후, Linux 바이너리를 Docker 볼륨에 넣으세요:
  - `/data/thor-lite/thor-lite` (이름은 달라도 됨)
- 실행 권한 부여:

```bash
bash scripts/apt_docker.sh bash -lc 'chmod +x /data/thor-lite/thor-lite'
```

### 2) 도움말 확인

```bash
bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --help
```

### 3) (예시) HA 추출물 / 다운로드 샘플 스캔

```bash
# HA mdmp 추출물(고신호 영역)
bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --folder /data/mdmp_extracted

# 다운로드 샘플(100개 코퍼스)
bash scripts/apt_docker.sh bash scripts/thor_lite.sh -- --folder /data/unzip_amd_100
```

## (옵션) LOKI(Neo23x0)로 스캔하기

LOKI는 Python 기반 IOC/YARA 스캐너이며, 시그니처는 `signature-base`를 사용합니다.  
참고: `loki.py`는 단독 파일이 아니라 `lib/`, `config/` 등 **전체 레포 구조가 필요**합니다. (upstream: `https://github.com/Neo23x0/Loki`)

이 프로젝트는 바이너리를 커밋하지 않고, Docker 볼륨(`/data`)에 **runtime clone**해서 실행하는 래퍼를 제공합니다: `scripts/loki.sh`

```bash
# 도움말
bash scripts/apt_docker.sh bash scripts/loki.sh -- --help

# HA mdmp 추출물(고신호 영역) 스캔
bash scripts/apt_docker.sh bash scripts/loki.sh --scan /data/mdmp_extracted

# 다운로드 샘플 코퍼스 스캔
bash scripts/apt_docker.sh bash scripts/loki.sh --scan /data/unzip_amd_100
```

기본적으로 `signature-base`는 아래 우선순위로 사용됩니다:
- `/data/rules/thirdparty/signature-base` (이미 받아둔 경우)
- 아니면 Loki 레포 내부의 `signature-base/`

## (옵션) HA region 파일을 region_000001.bin 형태로 export 후 YARA 스캔

Hybrid-Analysis `ha_dumps_unz/<dump_folder>/*.mdmp`는 (Minidump가 아니라) **region bytes 조각**인 경우가 많습니다.  
원하면 아래처럼 **일련번호 `region_*.bin`으로 export**해서 `yara -r`로 스캔할 수 있습니다.

```bash
# (예시) exec 또는 embedded-PE 후보만 export (권장)
bash scripts/apt_docker.sh python3 scripts/export_ha_regions.py \
  --src /data/ha_dumps_unz/<dump_folder> \
  --out /data/ha_regions_export/<dump_folder> \
  --filter exec_or_pe

# 스캔
bash scripts/apt_docker.sh bash -lc '
yara -r -p 4 -a 30 /data/yaraify/yarahub.compiled /data/ha_regions_export/<dump_folder> > /data/ha_regions_export/<dump_folder>/scan.txt || true
'
```

export 결과:
- `region_000001.bin` … (복사본)
- `manifest.csv` (원본 파일명/size/protect/is_exec/is_pe/mz_offset/pe_offset 매핑)


