#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Scan a target folder with all rule files under /data/rules (plus common compiled rulesets) and summarize results.

Default target:
  /data/mdmp_extracted

Outputs:
  /data/scan_all_rulesets/<timestamp>/
    summary.csv
    scans/<ruleset_name>.txt
    coverage/<ruleset_name>.csv

Usage:
  bash scripts/apt_docker.sh bash scripts/scan_all_rulesets.sh

Options:
  --target <path>    Target directory to scan (default: /data/mdmp_extracted)
  --threads <N>      YARA threads (-p) (default: 4)
  --timeout <N>      YARA timeout seconds (-a) (default: 30)
  --max <N>          Optional max rulesets to run (0 = no limit)

Notes:
  - For compiled rules, uses: yara -C
  - For text rules, uses: yara
  - If a rule file has a syntax error, it is skipped and recorded in summary.csv.
EOF
}

TARGET="/data/mdmp_extracted"
THREADS=4
TIMEOUT=30
MAX=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0;;
    --target) TARGET="${2:-}"; shift 2;;
    --threads) THREADS="${2:-}"; shift 2;;
    --timeout) TIMEOUT="${2:-}"; shift 2;;
    --max) MAX="${2:-}"; shift 2;;
    *) echo "Unknown arg: $1" >&2; usage >&2; exit 2;;
  esac
done

if [[ ! -d "${TARGET}" ]]; then
  echo "ERROR: target directory not found: ${TARGET}" >&2
  exit 2
fi

TS="$(date +%Y%m%d_%H%M%S)"
OUT_BASE="/data/scan_all_rulesets/${TS}"
SCAN_DIR="${OUT_BASE}/scans"
COV_DIR="${OUT_BASE}/coverage"
mkdir -p "${SCAN_DIR}" "${COV_DIR}"

SUMMARY="${OUT_BASE}/summary.csv"
echo "ruleset_name,rule_path,rule_type,scan_target,scan_lines,unique_files,folders_detected,folders_total,error" > "${SUMMARY}"

TMP_EMPTY="/tmp/empty.bin"
: > "${TMP_EMPTY}"

discover_rulesets() {
  # Prefer compiled rulesets if present
  local -a r=()
  [[ -f /data/yaraify/yarahub.compiled ]] && r+=("/data/yaraify/yarahub.compiled")
  [[ -f /data/rules/thirdparty/reversinglabs-yara.compiled ]] && r+=("/data/rules/thirdparty/reversinglabs-yara.compiled")
  [[ -f /data/rules/thirdparty/signature-base.compiled ]] && r+=("/data/rules/thirdparty/signature-base.compiled")

  # Malpedia rules in /data/rules/malpedia/*.yar (skip known broken backups/zips)
  if [[ -d /data/rules/malpedia ]]; then
    while IFS= read -r f; do
      case "$f" in
        *.zip|*.broken.*) continue;;
      esac
      r+=("$f")
    done < <(find /data/rules/malpedia -maxdepth 1 -type f \( -name "*.yar" -o -name "*.yara" \) -print | sort)
  fi

  printf '%s\n' "${r[@]}"
}

run_one() {
  local rule_path="$1"
  local base
  base="$(basename "$rule_path")"
  local ruleset_name="${base%.*}"
  ruleset_name="${ruleset_name//[^A-Za-z0-9_.-]/_}"

  local rule_type="text"
  local -a cmd=(yara -r -p "${THREADS}" -a "${TIMEOUT}")
  if [[ "$rule_path" == *.compiled || "$rule_path" == *.yarac ]]; then
    rule_type="compiled"
    cmd=(yara -C -r -p "${THREADS}" -a "${TIMEOUT}")
  fi

  # Syntax check for text rules (fast) - if broken, record and skip.
  if [[ "${rule_type}" == "text" ]]; then
    local err
    err="$("${cmd[@]}" "${rule_path}" "${TMP_EMPTY}" 2>&1 >/dev/null)"
    # Some YARA builds return 0 even for no-match; rely on presence of "error:" in stderr.
    if echo "${err}" | grep -qi '^error:'; then
      echo "${ruleset_name},${rule_path},${rule_type},${TARGET},0,0,0,0,\"${err//\"/\"\"}\"" >> "${SUMMARY}"
      return 0
    fi
  fi

  local scan_out="${SCAN_DIR}/${ruleset_name}.txt"
  "${cmd[@]}" "${rule_path}" "${TARGET}" > "${scan_out}" 2>/tmp/yara_scan_err.txt || true

  local scan_lines unique_files
  scan_lines="$(wc -l < "${scan_out}" | tr -d ' ')"
  unique_files="$(awk '{print $2}' "${scan_out}" | sort -u | wc -l | tr -d ' ')"

  local cov_csv="${COV_DIR}/${ruleset_name}.csv"
  local folders_total folders_detected
  # folder coverage expects root dir where immediate children are folders.
  folders_total="$(find "${TARGET}" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  folders_detected="0"
  if [[ "${folders_total}" != "0" ]]; then
    python3 /work/scripts/yara_folder_coverage.py --in "${scan_out}" --root "${TARGET}" --out "${cov_csv}" >/tmp/cov_log.txt 2>&1 || true
    folders_detected="$(awk -F' ' '$1=="folders_detected"{print $2}' /tmp/cov_log.txt | tail -1 | tr -d ' ' || true)"
    [[ -z "${folders_detected}" ]] && folders_detected="0"
  else
    echo "folder,detected,matched_rules" > "${cov_csv}"
  fi

  echo "${ruleset_name},${rule_path},${rule_type},${TARGET},${scan_lines},${unique_files},${folders_detected},${folders_total}," >> "${SUMMARY}"
}

count=0
while IFS= read -r rule; do
  [[ -z "${rule}" ]] && continue
  count=$((count + 1))
  if [[ "${MAX}" != "0" && "${count}" -gt "${MAX}" ]]; then
    break
  fi
  echo "[*] (${count}) scanning with: ${rule}"
  run_one "${rule}"
done < <(discover_rulesets)

echo "[*] done"
echo "summary: ${SUMMARY}"


