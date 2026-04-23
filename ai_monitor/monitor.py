import os
import time
from collections import defaultdict, deque

import csv
from pathlib import Path

import requests


HUB_URL = os.getenv("HUB_URL", "http://hub:8000")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
RUN_ID = os.getenv("RUN_ID", "run_default")

WINDOW_SIZE = 5

THRESHOLDS = {
    "traffic_rate": 70.0,
    "cpu_load": 70.0,
    "memory_usage": 85.0,
    "temperature": 75.0,
    "battery_level": 15.0,
}


def wait_for_hub(max_attempts: int = 30, delay: int = 2):
    print(f"Waiting for hub at {HUB_URL} ...", flush=True)
    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.get(f"{HUB_URL}/status", timeout=5)
            if r.status_code == 200:
                print("Hub is ready for AI monitor", flush=True)
                return
        except requests.RequestException as exc:
            print(f"[attempt {attempt}/{max_attempts}] hub not ready yet: {exc}", flush=True)

        time.sleep(delay)

    raise RuntimeError("Hub did not become ready for AI monitor in time")


def fetch_telemetry():
    r = requests.get(f"{HUB_URL}/telemetry?limit=200", timeout=5)
    r.raise_for_status()
    return r.json()


def fetch_devices():
    r = requests.get(f"{HUB_URL}/devices", timeout=5)
    r.raise_for_status()
    return r.json()


def send_action(device_id: str, action: str, reason: str):
    payload = {
        "device_id": device_id,
        "action": action,
        "reason": reason,
    }
    r = requests.post(f"{HUB_URL}/trust-action", json=payload, timeout=5)
    r.raise_for_status()
    return r.json()


def main():
    print("AI monitor started", flush=True)
    wait_for_hub()

    experiments_dir = Path("/app/experiments")
    experiments_dir.mkdir(parents=True, exist_ok=True)

    detection_csv_path = experiments_dir / "detection_metrics.csv"
    detection_file_exists = detection_csv_path.exists()

    detection_csv_file = open(detection_csv_path, "a", newline="")
    detection_writer = csv.writer(detection_csv_file)

    if not detection_file_exists:
        detection_writer.writerow([
            "run_id",
            "timestamp",
            "monitor_cycle",
            "device_id",
            "decision",
            "action_sent",
            "device_status",
            "trigger_metric",
            "trigger_avg",
            "trigger_threshold",
            "reason_count",
        ])
    monitor_cycle = 0

    while True:
        try:
            monitor_cycle += 1

            telemetry = fetch_telemetry()
            devices = fetch_devices()

            grouped = defaultdict(lambda: defaultdict(lambda: deque(maxlen=WINDOW_SIZE)))

            for event in telemetry:
                device_id = event["device_id"]
                metric = event["metric"]
                value = event["value"]
                grouped[device_id][metric].append(value)

            now_ts = time.time()

            for device_id, metrics in grouped.items():
                if device_id not in devices:
                    continue

                state = devices[device_id]
                device_status = state["status"]
                decision = "allow"
                action_sent = 0
                trigger_metric = ""
                trigger_avg = ""
                trigger_threshold = ""
                if state["status"] in {"banned", "quarantined"}:
                    continue

                reasons = []

                for metric_name, values in metrics.items():
                    if metric_name not in THRESHOLDS:
                        continue

                    if len(values) < WINDOW_SIZE:
                        continue

                    avg_recent = sum(values) / len(values)
                    threshold = THRESHOLDS[metric_name]

                    if metric_name == "battery_level":
                        if avg_recent < threshold:
                            reasons.append(f"{metric_name} avg={avg_recent:.2f} < {threshold:.2f}")
                            if not trigger_metric:
                                trigger_metric = metric_name
                                trigger_avg = round(avg_recent, 4)
                                trigger_threshold = threshold
                    else:
                        if avg_recent > threshold:
                            reasons.append(f"{metric_name} avg={avg_recent:.2f} > {threshold:.2f}")
                            if not trigger_metric:
                                trigger_metric = metric_name
                                trigger_avg = round(avg_recent, 4)
                                trigger_threshold = threshold

                if reasons:
                    decision = "quarantine"
                    action_sent = 1
                    reason_text = "AI monitor detected anomalous metrics: " + ", ".join(reasons)
                    result = send_action(device_id, "quarantine", reason_text)
                    print(f"AI action: {result}", flush=True)

                detection_writer.writerow([
                    RUN_ID,
                    now_ts,
                    monitor_cycle,
                    device_id,
                    decision,
                    action_sent,
                    device_status,
                    trigger_metric,
                    trigger_avg,
                    trigger_threshold,
                    len(reasons),
                ])

                detection_csv_file.flush()

        except Exception as exc:
            print(f"AI monitor error: {exc}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
