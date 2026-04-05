Sysdig capture **.scap** files, and use falco-replay to replay the attacks and baseline,
```bash
# baseline
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/scap/sysdig_scap/20260403_142412_baseline.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/scap/falco_replay/falco_baseline.log

# bias
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/scap/sysdig_scap/20260403_143022_bias.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/scap/falco_replay/falco_bias.log

# delay
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/scap/sysdig_scap/20260403_143526_delay.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/scap/falco_replay/falco_delay.log

# replay_zero
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/scap/sysdig_scap/20260403_143739_replay_zero.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/scap/falco_replay/falco_replay_zero.log

# bias_forced
sudo docker run --rm -it \
    --name falco \
    -v /home/hfh/scap/sysdig_scap/20260403_144034_bias_forced.scap:/capture.scap:ro \
    falcosecurity/falco:0.43.0 \
    falco -o engine.kind=replay -o engine.replay.capture_file=/capture.scap \
    2>&1 | sudo tee /home/hfh/scap/falco_replay/falco_bias_forced.log
```
