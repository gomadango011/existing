#!/usr/bin/env bash
set -u

WAF="./waf"
SCENARIO="random-outband"

# ===== experiment params =====
RUN_COUNT=20
TIME=30

# 固定条件
NODES=600
END_DISTANCE=800

# WHリンク長（WH_SIZE）
WH_SIZES=(300 400 500 600)

# ===== output dir (auto increment if exists) =====
ROOT_DIR="results/outand/nohello"
BASE_NAME="WHdetectionrate"
mkdir -p "${ROOT_DIR}"

BASE_DIR="${ROOT_DIR}/${BASE_NAME}"
if [[ -e "${BASE_DIR}" ]]; then
  n=1
  while :; do
    CANDIDATE=$(printf "%s_%03d" "${BASE_DIR}" "${n}")
    if [[ ! -e "${CANDIDATE}" ]]; then
      BASE_DIR="${CANDIDATE}"
      break
    fi
    n=$((n + 1))
  done
fi

LOG_DIR="${BASE_DIR}/logs"
mkdir -p "${LOG_DIR}"

FAILED_LOG="${BASE_DIR}/failed.log"
: > "${FAILED_LOG}"

echo "[INFO] start: $(date)"
echo "[INFO] base output dir: ${BASE_DIR}"

if [[ ! -x "${WAF}" ]]; then
  echo "[ERROR] ${WAF} not found or not executable. Run this script from ns-3 root."
  exit 1
fi

for WH in "${WH_SIZES[@]}"; do
  # 例: results/outand/nohello/WHdetectionrate_001/WHsize300.csv
  OUT="${BASE_DIR}/WHsize${WH}.csv"
  [[ -f "${OUT}" ]] || : > "${OUT}"  # 空ファイル作成（C++側ヘッダー判定用）

  echo "[INFO] WH_size=${WH} -> ${OUT}"

  for ((i=1; i<=RUN_COUNT; i++)); do
    STDOUT_LOG="${LOG_DIR}/WHsize${WH}_seed_${i}.out"
    STDERR_LOG="${LOG_DIR}/WHsize${WH}_seed_${i}.err"

    # forwardmode=1（nohello）
    # ※ここでは --size をノード数として使う前提（元スクリプト踏襲）
    RUN_STR="${SCENARIO} --size=${NODES} --time=${TIME} --WH_size=${WH} --end_distance=${END_DISTANCE} --iteration=${i} --result_file=${OUT} --forwardmode=1"

    echo "[RUN] ${WAF} --run \"${RUN_STR}\"" | tee -a "${STDOUT_LOG}"
    "${WAF}" --run "${RUN_STR}" > "${STDOUT_LOG}" 2> "${STDERR_LOG}"
    RET=$?

    if [[ ${RET} -ne 0 ]]; then
      echo "[FAIL] WH=${WH} seed=${i} (exit=${RET})" | tee -a "${FAILED_LOG}"
      continue
    fi

    echo "[OK] WH=${WH} seed=${i}"
  done
done

echo "[INFO] done: $(date)"
echo "[INFO] failed log: ${FAILED_LOG}"
echo "[INFO] outputs are under: ${BASE_DIR}"
