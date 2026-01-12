#!/usr/bin/env bash
set -eu

WAF="./waf"
SCENARIO="random-noWH"

RUN_COUNT=20
TIME=30
END_DISTANCE=800

SIZES=(400 500 600 700)

ROOT_DIR="result_existing/noWH"
BASE_NAME="false_detection_rate"
mkdir -p "${ROOT_DIR}"

BASE_DIR="${ROOT_DIR}/${BASE_NAME}"
if [[ -e "${BASE_DIR}" ]]; then
  n=1
  while :; do
    cand=$(printf "%s_%03d" "${BASE_DIR}" "${n}")
    [[ -e "${cand}" ]] || { BASE_DIR="${cand}"; break; }
    n=$((n+1))
  done
fi

LOG_DIR="${BASE_DIR}/logs"
mkdir -p "${LOG_DIR}"
FAILED_LOG="${BASE_DIR}/failed.log"
: > "${FAILED_LOG}"

echo "[INFO] output dir: ${BASE_DIR}"

for SIZE in "${SIZES[@]}"; do
  OUT="${BASE_DIR}/size_${SIZE}.csv"
  [[ -f "${OUT}" ]] || : > "${OUT}"

  echo "[INFO] size=${SIZE} -> ${OUT}"

  for ((i=1; i<=RUN_COUNT; i++)); do
    STDOUT_LOG="${LOG_DIR}/size_${SIZE}_iter_${i}.out"
    STDERR_LOG="${LOG_DIR}/size_${SIZE}_iter_${i}.err"

    RUN_STR="${SCENARIO} --size=${SIZE} --time=${TIME} --end_distance=${END_DISTANCE} --iteration=${i} --result_file=${OUT}"

    echo "[RUN] ${WAF} --run \"${RUN_STR}\"" >> "${STDOUT_LOG}"
    "${WAF}" --run "${RUN_STR}" > "${STDOUT_LOG}" 2> "${STDERR_LOG}" || {
      echo "[FAIL] size=${SIZE} iter=${i}" | tee -a "${FAILED_LOG}"
    }
  done
done

echo "[INFO] done. failed log: ${FAILED_LOG}"
