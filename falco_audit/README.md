Use docker to install falco,
First of all, we need to install docker.
```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Use these commands to check.
```bash
docker --version
sudo docker run --rm hello-world
```

```bash
sudo docker run --rm -it \
  --name falco \
  -v /home/pi/test/logs/capture.scap:/capture.scap:ro \
  falcosecurity/falco:0.43.0 \
  falco -o engine.kind=replay -o replay.capture_file=/capture.scap
```

```bash
sudo docker run --rm -it \
  --name falco-live \
  --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  -v /home/pi/test-v3/logs/falco-audit:/captures
  falcosecurity/falco:0.43.0 \
  falco
  -o engine.kind=modern_ebpf
  -o capture.enabled=true
  -o capture.mode=all_rules
  -o capture.path_prefix=/captures/cps
  -o capture.default_duration=40000
```

And we need to touch a rule file, for example **cps_rules.yml** in /home/pi/falco/. **I choose not use new rule file**.
```
- list: cps_attacker_bins
  items: [attacker_bias, attacker_delay, attacker_replay]

- macro: cps_attacker_proc
  condition: proc.name in (cps_attacker_bins)

- rule: CPS Memory Tamper Via ptrace or process_vm_writev
  desc: Detect ptrace/process_vm_* behavior from CPS attack binaries
  condition: cps_attacker_proc and evt.type in (ptrace, process_vm_readv, process_vm_writev)
  output: "[CPS_ATTACK_MEM] user=%user.name proc=%proc.name pid=%proc.pid evt=%evt.type cmd=%proc.cmdline"
  priority: CRITICAL
  tags: [cps, attack, ptrace]

- rule: CPS Timing Attack Via STOP CONT Signals
  desc: Detect delay attack signal manipulation
  condition: cps_attacker_proc and evt.type in (kill, pidfd_send_signal)
  output: "[CPS_ATTACK_DELAY] user=%user.name proc=%proc.name pid=%proc.pid evt=%evt.type cmd=%proc.cmdline"
  priority: WARNING
  tags: [cps, attack, signal]

- rule: CPS Replay Attack UDP Burst
  desc: Detect replay sender behavior
  condition: proc.name=attacker_replay and evt.type=sendto
  output: "[CPS_ATTACK_REPLAY] user=%user.name proc=%proc.name pid=%proc.pid evt=%evt.type fd=%fd.name cmd=%proc.cmdline"
  priority: NOTICE
  tags: [cps, attack, replay]
```

Now, we need to start falco,
```bash
sudo docker run --rm -it \
  --name falco-live \
  --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /proc:/host/proc:ro \
  -v /etc:/host/etc:ro \
  -v /home/pi/falco/cps_rules.yaml:/etc/falco/cps_rules.yaml:ro \
  falcosecurity/falco:0.43.0 \
  falco -o engine.kind=modern_ebpf -r /etc/falco/cps_rules.yaml
```
