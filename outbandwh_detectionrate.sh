#!/usr/bin/env bash
set -u

WAF="./waf"
SCENARIO="random-outband"

RUN_COUNT=20
TIME=30
SIZE=600
END_DISTANCE=800
WH_SIZES=(300 400 500 600)

ROOT_DIR="result_existing/outband"
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
  echo "[ERROR] ${WAF} not found or not executable. Run this script from ns-3.30 root."
  exit 1
fi

for WH in "${WH_SIZES[@]}"; do
  WH_DIR="${BASE_DIR}/WHsize_${WH}"
  mkdir -p "${WH_DIR}"

  OUT="${WH_DIR}/result.csv"
  [[ -f "${OUT}" ]] || : > "${OUT}"

  echo "[INFO] WH_size=${WH} -> ${OUT}"

  for ((i=1; i<=RUN_COUNT; i++)); do
    STDOUT_LOG="${LOG_DIR}/wh_${WH}_iter_${i}.out"
    STDERR_LOG="${LOG_DIR}/wh_${WH}_iter_${i}.err"

    RUN_STR="${SCENARIO} --size=${SIZE} --time=${TIME} --WH_size=${WH} --end_distance=${END_DISTANCE} --iteration=${i} --result_file=${OUT}"

    echo "[RUN] ${WAF} --run \"${RUN_STR}\"" | tee -a "${STDOUT_LOG}"
    "${WAF}" --run "${RUN_STR}" > "${STDOUT_LOG}" 2> "${STDERR_LOG}"
    RET=$?

    if [[ ${RET} -ne 0 ]]; then
      echo "[FAIL] WH=${WH} iter=${i} (exit=${RET})" | tee -a "${FAILED_LOG}"
      continue
    fi

    echo "[OK] WH=${WH} iter=${i}"
  done
done

echo "[INFO] done: $(date)"
echo "[INFO] failed log: ${FAILED_LOG}"
echo "[INFO] outputs are under: ${BASE_DIR}"
