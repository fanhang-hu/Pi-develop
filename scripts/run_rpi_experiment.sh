#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MODE="baseline"
DURATION_SEC=30
OUT_BASE_DIR="${ROOT_DIR}/logs"

PERIOD_MS=100
SEND_PERIOD_MS=100
V2_SCALE="1.0"
V2_OFFSET="0.0"

HOST_MODE="controller"  # controller|none
HOST_IP="127.0.0.1"
HOST_PORT=19000
GATEWAY_PORT=19100
GATEWAY_IP="127.0.0.1"
SENSOR_PERIOD_FILE="/tmp/cps_sensor_period_ms"

ATTACK_BIAS=50.0
ATTACK_INTERVAL_MS=100
ATTACK_ROUNDS=120
ATTACK_SYMBOL="g_latest_measurement"
ATTACK_PROC_NAME="gateway"

DELAY_HOLD_MS=800
DELAY_INTERVAL_MS=300
DELAY_ROUNDS=20
DELAY_JITTER_MS=20
DELAY_PERIOD_MS=400

REPLAY_HOLD_MS=800
REPLAY_INTERVAL_MS=500
REPLAY_ROUNDS=20
REPLAY_SEND_INTERVAL_MS=40
REPLAY_CAPTURE_MIN=20
REPLAY_WINDOW=12
REPLAY_JITTER_MS=20
REPLAY_PERIOD_MS=800

usage() {
  cat <<'USAGE_EOF'
Usage:
  ./scripts/run_rpi_experiment.sh [options]

Options:
  --mode baseline|bias|delay|replay
  --duration-sec N
  --out-dir DIR
  --period-ms N
  --send-period-ms N
  --v2-scale V
  --v2-offset V
  --host-mode controller|none
  --host-ip IP
  --host-port PORT
  --gateway-port PORT
  --gateway-ip IP
  --period-file PATH
USAGE_EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --duration-sec)
      DURATION_SEC="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_BASE_DIR="${2:-}"
      shift 2
      ;;
    --period-ms)
      PERIOD_MS="${2:-}"
      shift 2
      ;;
    --send-period-ms)
      SEND_PERIOD_MS="${2:-}"
      shift 2
      ;;
    --v2-scale)
      V2_SCALE="${2:-}"
      shift 2
      ;;
    --v2-offset)
      V2_OFFSET="${2:-}"
      shift 2
      ;;
    --host-mode)
      HOST_MODE="${2:-}"
      shift 2
      ;;
    --host-ip)
      HOST_IP="${2:-}"
      shift 2
      ;;
    --host-port)
      HOST_PORT="${2:-}"
      shift 2
      ;;
    --gateway-port)
      GATEWAY_PORT="${2:-}"
      shift 2
      ;;
    --gateway-ip)
      GATEWAY_IP="${2:-}"
      shift 2
      ;;
    --period-file)
      SENSOR_PERIOD_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[run_rpi_experiment] Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "${MODE}" != "baseline" && "${MODE}" != "bias" && "${MODE}" != "delay" && "${MODE}" != "replay" ]]; then
  echo "[run_rpi_experiment] --mode must be baseline, bias, delay, or replay" >&2
  exit 1
fi

if [[ "${HOST_MODE}" != "controller" && "${HOST_MODE}" != "none" ]]; then
  echo "[run_rpi_experiment] --host-mode must be controller or none" >&2
  exit 1
fi

need_rebuild=0
required_bins=(rpi_gateway attacker_bias attacker_delay attacker_replay)
if [[ "${HOST_MODE}" == "controller" ]]; then
  required_bins+=(controller)
fi

for b in "${required_bins[@]}"; do
  if [[ ! -x "${ROOT_DIR}/bin/${b}" ]]; then
    need_rebuild=1
  fi
done

if [[ "${need_rebuild}" -eq 1 ]]; then
  echo "[run_rpi_experiment] rebuilding binaries with make clean && make ..."
  (cd "${ROOT_DIR}" && make clean && make)
fi

timestamp="$(date +%Y%m%d_%H%M%S)"
run_dir="${OUT_BASE_DIR}/${timestamp}_rpi_${MODE}"
mkdir -p "${run_dir}"

sensor_log="${run_dir}/sensor.log"
gateway_log="${run_dir}/gateway.log"
controller_log="${run_dir}/controller.log"
attacker_log="${run_dir}/attacker.log"
run_info="${run_dir}/run_info.txt"
v1_file="${run_dir}/v1.csv"
v2_file="${run_dir}/v2.csv"

controller_pid=""
sensor_pid=""
gateway_pid=""
attacker_pid=""

cleanup() {
  set +e
  [[ -n "${attacker_pid}" ]] && kill "${attacker_pid}" 2>/dev/null
  [[ -n "${sensor_pid}" ]] && kill "${sensor_pid}" 2>/dev/null
  [[ -n "${gateway_pid}" ]] && kill "${gateway_pid}" 2>/dev/null
  [[ -n "${controller_pid}" ]] && kill "${controller_pid}" 2>/dev/null
  wait "${attacker_pid}" 2>/dev/null || true
  wait "${sensor_pid}" 2>/dev/null || true
  wait "${gateway_pid}" 2>/dev/null || true
  wait "${controller_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

cat >"${run_info}" <<EOF_INFO
mode=${MODE}
duration_sec=${DURATION_SEC}
period_ms=${PERIOD_MS}
send_period_ms=${SEND_PERIOD_MS}
v2_scale=${V2_SCALE}
v2_offset=${V2_OFFSET}
host_mode=${HOST_MODE}
host_ip=${HOST_IP}
host_port=${HOST_PORT}
gateway_ip=${GATEWAY_IP}
gateway_port=${GATEWAY_PORT}
period_file=${SENSOR_PERIOD_FILE}
EOF_INFO

if [[ "${HOST_MODE}" == "controller" ]]; then
  CPS_ACTUATOR_ENABLE=0 \
    "${ROOT_DIR}/bin/controller" >"${controller_log}" 2>&1 &
  controller_pid=$!
  echo "[run_rpi_experiment] controller pid=${controller_pid}"
else
  : >"${controller_log}"
fi

CPS_HOST_IP="${HOST_IP}" \
CPS_HOST_PORT="${HOST_PORT}" \
CPS_RPI_LISTEN_PORT="${GATEWAY_PORT}" \
CPS_SEND_PERIOD_MS="${SEND_PERIOD_MS}" \
CPS_PTRACE_COMPAT="${CPS_PTRACE_COMPAT:-1}" \
  "${ROOT_DIR}/bin/rpi_gateway" >"${gateway_log}" 2>&1 &

gateway_pid=$!
echo "[run_rpi_experiment] gateway pid=${gateway_pid}"

python3 "${ROOT_DIR}/scripts/rpi_vl53l1x_sensor.py" \
  --period-ms "${PERIOD_MS}" \
  --duration-s "${DURATION_SEC}" \
  --v1-file "${v1_file}" \
  --v2-file "${v2_file}" \
  --v2-scale "${V2_SCALE}" \
  --v2-offset "${V2_OFFSET}" \
  --out-ip "${GATEWAY_IP}" \
  --out-port "${GATEWAY_PORT}" \
  --period-file "${SENSOR_PERIOD_FILE}" >"${sensor_log}" 2>&1 &

sensor_pid=$!
echo "[run_rpi_experiment] sensor pid=${sensor_pid}"

sleep 2

if [[ "${MODE}" == "bias" ]]; then
  "${ROOT_DIR}/bin/attacker_bias" \
    "${gateway_pid}" \
    "${ATTACK_BIAS}" \
    "${ATTACK_INTERVAL_MS}" \
    "${ATTACK_ROUNDS}" \
    "${ATTACK_SYMBOL}" \
    "${ATTACK_PROC_NAME}" >"${attacker_log}" 2>&1 &
  attacker_pid=$!
  echo "[run_rpi_experiment] attacker pid=${attacker_pid}"
elif [[ "${MODE}" == "delay" ]]; then
  "${ROOT_DIR}/bin/attacker_delay" \
    "${sensor_pid}" \
    "${DELAY_HOLD_MS}" \
    "${DELAY_INTERVAL_MS}" \
    "${DELAY_ROUNDS}" \
    "sensor" \
    "${DELAY_JITTER_MS}" \
    "${SENSOR_PERIOD_FILE}" \
    "${DELAY_PERIOD_MS}" \
    "${PERIOD_MS}" >"${attacker_log}" 2>&1 &
  attacker_pid=$!
  echo "[run_rpi_experiment] attacker pid=${attacker_pid}"
elif [[ "${MODE}" == "replay" ]]; then
  "${ROOT_DIR}/bin/attacker_replay" \
    "${gateway_pid}" \
    "${sensor_log}" \
    "${REPLAY_HOLD_MS}" \
    "${REPLAY_INTERVAL_MS}" \
    "${REPLAY_ROUNDS}" \
    "gateway" \
    "${REPLAY_SEND_INTERVAL_MS}" \
    "${REPLAY_CAPTURE_MIN}" \
    "${REPLAY_WINDOW}" \
    "${REPLAY_JITTER_MS}" \
    "${SENSOR_PERIOD_FILE}" \
    "${REPLAY_PERIOD_MS}" \
    "${PERIOD_MS}" >"${attacker_log}" 2>&1 &
  attacker_pid=$!
  echo "[run_rpi_experiment] attacker pid=${attacker_pid}"
else
  : >"${attacker_log}"
fi

echo "[run_rpi_experiment] running for ${DURATION_SEC}s ..."
elapsed=0
while [[ "${elapsed}" -lt "${DURATION_SEC}" ]]; do
  sleep 1
  elapsed=$((elapsed + 1))
  if [[ -n "${sensor_pid}" ]] && ! kill -0 "${sensor_pid}" 2>/dev/null; then
    echo "[run_rpi_experiment] sensor exited early" >&2
    break
  fi
  if [[ -n "${gateway_pid}" ]] && ! kill -0 "${gateway_pid}" 2>/dev/null; then
    echo "[run_rpi_experiment] gateway exited early" >&2
    break
  fi
  if [[ "${HOST_MODE}" == "controller" && -n "${controller_pid}" ]] && ! kill -0 "${controller_pid}" 2>/dev/null; then
    echo "[run_rpi_experiment] controller exited early" >&2
    break
  fi
done

echo "[run_rpi_experiment] complete"
echo "[run_rpi_experiment] logs:"
echo "  ${sensor_log}"
echo "  ${gateway_log}"
echo "  ${controller_log}"
echo "  ${attacker_log}"
echo "  ${v1_file}"
echo "  ${v2_file}"
echo "  ${run_info}"
