#!/usr/bin/env python3
import argparse
import csv
import os
import signal
import socket
import sys
import time

import adafruit_vl53l1x
import board

DEFAULT_PERIOD_MS = 100
DEFAULT_DURATION_S = 30.0
DEFAULT_OUT_PORT = 19100
DEFAULT_PERIOD_FILE = "/tmp/cps_sensor_period_ms"


def _try_set(obj, name, value):
    if hasattr(obj, name):
        try:
            setattr(obj, name, value)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[WARN] set {name} failed: {exc}", file=sys.stderr)
    return False


def _try_call(obj, name, *args):
    if hasattr(obj, name):
        try:
            getattr(obj, name)(*args)
            return True
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[WARN] {name} failed: {exc}", file=sys.stderr)
    return False


def _set_proc_name(name: str) -> None:
    try:
        import ctypes
        import ctypes.util

        libc_path = ctypes.util.find_library("c")
        if not libc_path:
            return
        libc = ctypes.CDLL(libc_path, use_errno=True)
        PR_SET_NAME = 15
        libc.prctl(PR_SET_NAME, ctypes.c_char_p(name.encode("utf-8")), 0, 0, 0)
    except Exception:
        return


def _read_period_ms(path: str, current_ms: int) -> int:
    if not path:
        return current_ms
    try:
        with open(path, "r", encoding="ascii") as f:
            raw = f.read().strip()
        value = int(raw)
        if value > 0:
            return value
    except Exception:
        return current_ms
    return current_ms


def _ensure_period_file(path: str, period_ms: int) -> None:
    if not path:
        return
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="ascii") as f:
                f.write(f"{period_ms}\n")
    except Exception as exc:
        print(f"[WARN] unable to create period file {path}: {exc}", file=sys.stderr)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Raspberry Pi VL53L1X sensor poller with v1/v2 storage")
    parser.add_argument(
        "--mode",
        choices=("full", "save", "recv"),
        default=os.getenv("CPS_SENSOR_MODE", "full"),
        help="full=save+udp, save=save v1/v2 only, recv=print only",
    )
    parser.add_argument("--period-ms", type=int, default=int(os.getenv("CPS_SENSOR_PERIOD_MS", DEFAULT_PERIOD_MS)))
    parser.add_argument("--duration-s", type=float, default=float(os.getenv("CPS_SENSOR_DURATION_S", DEFAULT_DURATION_S)))
    parser.add_argument("--v1-file", default=os.getenv("CPS_V1_FILE", "v1.csv"))
    parser.add_argument("--v2-file", default=os.getenv("CPS_V2_FILE", "v2.csv"))
    parser.add_argument("--v2-scale", type=float, default=float(os.getenv("CPS_V2_SCALE", "1.0")))
    parser.add_argument("--v2-offset", type=float, default=float(os.getenv("CPS_V2_OFFSET", "0.0")))
    parser.add_argument("--out-ip", default=os.getenv("CPS_RPI_GATEWAY_IP", "127.0.0.1"))
    parser.add_argument("--out-port", type=int, default=int(os.getenv("CPS_RPI_GATEWAY_PORT", DEFAULT_OUT_PORT)))
    parser.add_argument("--period-file", default=os.getenv("CPS_SENSOR_PERIOD_FILE", DEFAULT_PERIOD_FILE))
    parser.add_argument("--proc-name", default=os.getenv("CPS_SENSOR_PROC_NAME", "sensor"))
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.period_ms <= 0:
        print("period-ms must be > 0", file=sys.stderr)
        return 1
    if args.mode in ("full", "save") and args.duration_s <= 0:
        print("duration-s must be > 0 for full/save mode", file=sys.stderr)
        return 1

    if args.out_port <= 0:
        print("out-port must be > 0", file=sys.stderr)
        return 1

    _set_proc_name(args.proc_name)
    _ensure_period_file(args.period_file, args.period_ms)

    try:
        i2c = board.I2C()
        sensor = adafruit_vl53l1x.VL53L1X(i2c)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"VL53L1X init failed: {exc}", file=sys.stderr)
        return 1

    _try_set(sensor, "distance_mode", 2)  # 2=long
    _try_set(sensor, "timing_budget", args.period_ms)
    _try_set(sensor, "inter_measurement_period", args.period_ms)

    sock = None
    if args.mode == "full":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    stop = False

    def on_sig(signo, _frame):
        nonlocal stop
        if signo in (signal.SIGINT, signal.SIGTERM):
            stop = True

    signal.signal(signal.SIGINT, on_sig)
    signal.signal(signal.SIGTERM, on_sig)

    _try_call(sensor, "start_ranging")

    start = time.monotonic()
    end = start + args.duration_s if args.duration_s > 0 else 0.0
    next_t = start
    seq = 0
    period_ms = args.period_ms
    v1_f = None
    v2_f = None
    v1_writer = None
    v2_writer = None

    if args.mode in ("full", "save"):
        v1_f = open(args.v1_file, "w", newline="", encoding="ascii")
        v2_f = open(args.v2_file, "w", newline="", encoding="ascii")
        v1_writer = csv.writer(v1_f)
        v2_writer = csv.writer(v2_f)
        v1_writer.writerow(["t_monotonic_s", "t_epoch_s", "seq", "distance_mm", "range_status"])
        v2_writer.writerow([
            "t_monotonic_s",
            "t_epoch_s",
            "seq",
            "v2_value",
            "distance_mm",
            "range_status",
            "scale",
            "offset",
        ])

    try:
        while not stop:
            now = time.monotonic()
            if end > 0 and now >= end:
                break

            updated_period = _read_period_ms(args.period_file, period_ms)
            if updated_period != period_ms:
                period_ms = updated_period
                _try_set(sensor, "inter_measurement_period", period_ms)
                next_t = now + (period_ms / 1000.0)
                print(f"[sensor] period_ms updated to {period_ms} via period file")

            sleep_s = next_t - now
            if sleep_s > 0:
                time.sleep(sleep_s)

            if hasattr(sensor, "data_ready"):
                t0 = time.monotonic()
                while not sensor.data_ready:
                    if time.monotonic() - t0 > 0.05:
                        break
                    time.sleep(0.001)

            now = time.monotonic()
            if not getattr(sensor, "data_ready", True):
                next_t += period_ms / 1000.0
                continue

            distance = getattr(sensor, "distance", None)
            status = ""

            _try_call(sensor, "clear_interrupt")

            if distance is None:
                next_t += period_ms / 1000.0
                continue

            t_mono = round(now - start, 6)
            t_epoch = round(time.time(), 6)
            v2_value = args.v2_scale * float(distance) + args.v2_offset

            if args.mode in ("full", "save"):
                v1_writer.writerow([t_mono, t_epoch, seq, distance, status])
                v1_f.flush()

                v2_writer.writerow([t_mono, t_epoch, seq, f"{v2_value:.6f}", distance, status, args.v2_scale, args.v2_offset])
                v2_f.flush()

            if args.mode == "full" and sock is not None:
                payload = f"{seq} {v2_value:.6f}".encode("ascii")
                try:
                    sock.sendto(payload, (args.out_ip, args.out_port))
                except Exception as exc:  # pylint: disable=broad-except
                    print(f"[WARN] sendto failed: {exc}", file=sys.stderr)

            if args.mode == "recv":
                print(f"当前距离：{distance} mm")
            else:
                print(f"[sensor] seq={seq} value={v2_value:.6f} raw={distance} status={status}")
            sys.stdout.flush()

            seq += 1
            next_t += period_ms / 1000.0
    finally:
        if v1_f:
            v1_f.close()
        if v2_f:
            v2_f.close()

    _try_call(sensor, "stop_ranging")
    return 0


if __name__ == "__main__":
    sys.exit(main())
