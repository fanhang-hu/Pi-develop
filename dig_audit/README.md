First of all, we need to install sysdig.

Update and install requirments,
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install ca-certificates curl gpg ncurses-term dkms build-essential -y
```

Add sysdig GPG key,
```bash
curl -fsSL https://download.sysdig.com/DRAIOS-GPG-KEY.public | sudo gpg --dearmor -o /usr/share/keyrings/sysdig.gpg

printf '%s\n' \
  'Types: deb' \
  'URIs: https://download.sysdig.com/stable/deb' \
  "Suites: stable-$(dpkg --print-architecture)/" \
  'Signed-By: /usr/share/keyrings/sysdig.gpg' \
  | sudo tee /etc/apt/sources.list.d/sysdig.sources > /dev/null
```

Refresh and install kernal module,
```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) sysdig -y
```

You can use the following cmd to check,
```
sudo apt update
sudo apt install linux-headers-$(uname -r) sysdig -y
```

Before auditing, we need to touch a new run_case.sh,
```
#!/usr/bin/env bash
set -euo pipefail

AUDIT_DIR="${AUDIT_DIR:-sysdig_audit}"
SCAP_DIR="${AUDIT_DIR}/scap"
TXT_DIR="${AUDIT_DIR}/txt"
SUMMARY_DIR="${AUDIT_DIR}/summary"
SUMMARY_FILE="${SUMMARY_DIR}/scap_list.txt"

# 统一过滤器：进程 + 关键系统调用 + period 文件
FILTER='(proc.name in (gateway,rpi_gateway,controller,python3,attacker_bias,attacker_delay,attacker_replay,bash,sh)) or (evt.type in (ptrace,process_vm_writev,process_vm_readv,pidfd_send_signal,kill,openat,write,sendto,recvfrom,nanosleep)) or (fd.name contains cps_sensor_period_ms)'

usage() {
  cat <<'EOF'
用法:
  ./run_case.sh <name> <capture_seconds> -- <experiment command...>

示例:
  ./run_case.sh baseline 55 -- ./scripts/run_rpi_experiment.sh --mode baseline --duration-sec 30
  ./run_case.sh bias 55 -- ./scripts/run_rpi_experiment.sh --mode bias --duration-sec 30
EOF
}

ensure_driver() {
  if [[ ! -e /dev/scap0 ]]; then
    echo "[run_case] /dev/scap0 不存在，尝试加载 scap 模块..."
    sudo modprobe scap || true
  fi

  if [[ ! -e /dev/scap0 ]]; then
    echo "[run_case] 错误: scap 驱动不可用（/dev/scap0 不存在）"
    return 1
  fi
}

run_case() {
  local name="$1"
  local cap_sec="$2"
  shift 2

  mkdir -p "${SCAP_DIR}" "${TXT_DIR}" "${SUMMARY_DIR}"
  touch "${SUMMARY_FILE}"

  local ts scap logf cap_pid exp_rc=0
  ts="$(date +%Y%m%d_%H%M%S)"
  scap="${SCAP_DIR}/${ts}_${name}.scap"
  logf="${TXT_DIR}/${ts}_${name}_capture.log"

  echo "[run_case] start capture: ${name} -> ${scap}"

  # 提前认证，避免后台 sudo 等密码造成“假卡死”
  sudo -v

  # 防止并发消费者冲突（可选保守做法）
  sudo pkill -f '^sysdig ' 2>/dev/null || true
  sleep 1

  # 启动采集
  sudo timeout -s INT "${cap_sec}" \
    sysdig -w "${scap}" "${FILTER}" \
    > "${logf}" 2>&1 &
  cap_pid=$!

  # 给 sysdig 2 秒启动时间
  sleep 2

  if ! kill -0 "${cap_pid}" 2>/dev/null; then
    echo "[run_case] sysdig 启动失败，请检查: ${logf}"
    tail -n 30 "${logf}" || true
    return 1
  fi

  # 执行实验命令
  "$@" || exp_rc=$?

  # 实验结束后主动停止采集，避免等满 cap_sec
  kill -INT "${cap_pid}" 2>/dev/null || true
  wait "${cap_pid}" 2>/dev/null || true

  if [[ -s "${scap}" ]]; then
    echo "${name},${scap}" >> "${SUMMARY_FILE}"
    echo "[run_case] done: ${name}"
  else
    echo "[run_case] 采集文件为空，请检查: ${logf}"
    return 1
  fi

  return "${exp_rc}"
}

main() {
  if [[ $# -lt 4 ]]; then
    usage
    exit 1
  fi

  local name="$1"
  local cap_sec="$2"
  shift 2

  if [[ "$1" != "--" ]]; then
    echo "[run_case] 参数错误: 第 3 个参数必须是 --"
    usage
    exit 1
  fi
  shift

  if [[ -z "${name}" || -z "${cap_sec}" ]]; then
    usage
    exit 1
  fi

  ensure_driver
  run_case "${name}" "${cap_sec}" "$@"
}

main "$@"
```

And we need to deal with several problems to find sysdig,
```bash
sysdig --version
ls -l /dev/scap* 2>/dev/null || echo "no /dev/scap*"
lsmod | grep scap || echo "scap module not loaded"
sudo modprobe scap || true
ls -l /dev/scap* 2>/dev/null || echo "still no /dev/scap*"
```

Now, you can start auditing,
```bash
mkdir -p sysdig_audit/{scap,txt,summary}
: > sysdig_audit/summary/scap_list.txt
```

and,
```bash
./run_case.sh baseline 40 -- ./scripts/run_rpi_experiment.sh --mode baseline --duration-sec 30

./run_case.sh bias 40 -- ./scripts/run_rpi_experiment.sh --mode bias --duration-sec 30
./run_case.sh delay 40 -- ./scripts/run_rpi_experiment.sh --mode delay --duration-sec 30
./run_case.sh replay 50 -- ./scripts/run_rpi_experiment.sh --mode replay --duration-sec 40
./run_case.sh replay_zero 50 -- ./scripts/run_rpi_experiment.sh --mode replay_zero --duration-sec 40
./run_case.sh replay_zero_forced 50 -- ./scripts/run_rpi_experiment.sh --mode replay_zero --duration-sec 40 --replay-force-start-sec 10 --replay-force-end-sec 20 --replay-force-value 0.0
./run_case.sh bias_forced_burst 40 -- ./scripts/run_rpi_experiment.sh --mode bias --duration-sec 30 --bias-force-start-sec 10 --bias-force-end-sec 20 --attack-interval-ms 1 --attack-burst-writes 10 --attack-burst-gap-ms 0
```

run the following in the terminal,
```bash
find sysdig_audit/scap -type f -name "*.scap" | sort > sysdig_audit/summary/scap_paths.txt
```

```bash
awk -F/ '
{
  file=$NF
  case_name=file
  sub(/^[0-9]{8}_[0-9]{6}_/, "", case_name)
  sub(/\.scap$/, "", case_name)
  print case_name "," $0
}
' sysdig_audit/summary/scap_paths.txt > sysdig_audit/summary/scap_list.txt

echo "case,ptrace_bias,vmwrite_bias,delay_period_write,replay_period_write,replay_sendto,delay_signal,replay_signal,total_events" > sysdig_audit/summary/event_counts.csv

while IFS=, read -r name scap; do
  [ -z "$name" ] && continue

  c1=$(sysdig -r "$scap" -p "%evt.type %proc.name" "proc.name=attacker_bias and evt.type=ptrace" | wc -l | tr -d " ")
  c2=$(sysdig -r "$scap" -p "%evt.type %proc.name" "proc.name=attacker_bias and evt.type=process_vm_writev" | wc -l | tr -d " ")
  c3=$(sysdig -r "$scap" -p "%evt.type %proc.name %fd.name" "proc.name=attacker_delay and evt.type=write and fd.name contains cps_sensor_period_ms" | wc -l | tr -d " ")
  c4=$(sysdig -r "$scap" -p "%evt.type %proc.name %fd.name" "proc.name=attacker_replay and evt.type=write and fd.name contains cps_sensor_period_ms" | wc -l | tr -d " ")
  c5=$(sysdig -r "$scap" -p "%evt.type %proc.name" "proc.name=attacker_replay and evt.type=sendto" | wc -l | tr -d " ")
  c6=$(sysdig -r "$scap" -p "%evt.type %proc.name %evt.args" "proc.name=attacker_delay and evt.type in (kill,pidfd_send_signal)" | wc -l | tr -d " ")
  c7=$(sysdig -r "$scap" -p "%evt.type %proc.name %evt.args" "proc.name=attacker_replay and evt.type in (kill,pidfd_send_signal)" | wc -l | tr -d " ")
  c8=$(sysdig -r "$scap" -p "%evt.num" "proc.name in (gateway,rpi_gateway,controller,python3,attacker_bias,attacker_delay,attacker_replay)" | wc -l | tr -d " ")

  echo "${name},${c1},${c2},${c3},${c4},${c5},${c6},${c7},${c8}" >> sysdig_audit/summary/event_counts.csv
done < sysdig_audit/summary/scap_list.txt

column -s, -t sysdig_audit/summary/event_counts.csv
```

--------------------------------------------------------------------------
Now, we get several .scap file, if we want to use **NodLink** to identify the attacks, we need to transfer these scap files to **.json** format.

First of all, we need to locate to scap,
```bash
cd scap
```

And run the following command in the terminal, remember to update the scap file name,
```bash
SCAP=20260403_144034_bias_forced.scap
USV=scap2json/bias_forced/bias_forced.fields.usv
JSONL=scap2json/bias_forced/bias_forced.nodlink.jsonl
JSON=scap2json/bias_forced/bias_forced.nodlink.json

DELIM=$'\x1f'
FMT="%evt.args${DELIM}%evt.num${DELIM}%evt.rawtime${DELIM}%evt.type${DELIM}%fd.name${DELIM}%proc.cmdline${DELIM}%proc.name${DELIM}%proc.pcmdline${DELIM}%proc.pname"

sysdig -r "$SCAP" -p "$FMT" > "$USV"

jq -Rc '
split("\u001f") as $f |
{
  "evt.args": ($f[0] // ""),
  "evt.num": (($f[1] // "") | tonumber? // null),
  "evt.time": (($f[2] // "") | tonumber? // null),
  "evt.type": ($f[3] // ""),
  "fd.name": ($f[4] // ""),
  "proc.cmdline": ($f[5] // ""),
  "proc.name": ($f[6] // ""),
  "proc.pcmdline": ($f[7] // ""),
  "proc.pname": ($f[8] // "")
}
' "$USV" > "$JSONL"

jq -s '.' "$JSONL" > "$JSON"
```

```bash
jq -c '.[]' bias_forced.json > output.json
```

Now, we will get json files and **NodLink** need to use proc.cmdline to identify, so we need to use some commands to grep,
```bash
grep '"proc.cmdline"' baseline.nodlink.json | sort -u
grep '"proc.cmdline"' bias.nodlink.json | sort -u
grep '"proc.cmdline"' bias_forced.nodlink.json | sort -u
grep '"proc.cmdline"' delay.nodlink.json | sort -u
grep '"proc.cmdline"' replay_zero.nodlink.json | sort -u
```
