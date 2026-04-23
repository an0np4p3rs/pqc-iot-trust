import base64
import hashlib
import os
import random
import time
import csv
from pathlib import Path

import requests

from oqs_kem import Kem
from oqs_sig import sign_message


HUB_URL = os.getenv("HUB_URL", "http://hub:8000")
DEVICE_COUNT = int(os.getenv("DEVICE_COUNT", "3"))
RUN_FOREVER = os.getenv("RUN_FOREVER", "true").lower() == "true"
RUN_ID = os.getenv("RUN_ID", "run_default")
EXPERIMENTS_DIR = Path(os.getenv("EXPERIMENTS_DIR", "/app/experiments"))
JOIN_CSV = EXPERIMENTS_DIR / "join_metrics.csv"
TELEMETRY_CSV = EXPERIMENTS_DIR / "telemetry_metrics.csv"
ANOMALY_PLAN_CSV = EXPERIMENTS_DIR / "anomaly_events.csv"

MANUFACTURER_SIG_ALG = os.getenv("MANUFACTURER_SIG_ALG", "Dilithium2")
MANUFACTURER_PUBLIC_KEY_B64 = os.getenv("MANUFACTURER_PUBLIC_KEY_B64", "")
MANUFACTURER_SECRET_KEY_B64 = os.getenv("MANUFACTURER_SECRET_KEY_B64", "")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def firmware_hash_for(device_id: str) -> str:
    return sha256_hex(f"firmware::{device_id}::v1.0.0".encode())


def ensure_experiments_dir():
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)


def append_csv_row(path: Path, header: list[str], row: list):
    file_exists = path.exists()

    with path.open("a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(header)
        writer.writerow(row)


def wait_for_hub(max_attempts: int = 30, delay: int = 2):
    print(f"Waiting for hub at {HUB_URL} ...", flush=True)
    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.get(f"{HUB_URL}/status", timeout=5)
            if r.status_code == 200:
                print("Hub is ready", flush=True)
                return True
        except requests.RequestException as exc:
            print(f"[attempt {attempt}/{max_attempts}] hub not ready yet: {exc}", flush=True)

        time.sleep(delay)

    raise RuntimeError("Hub did not become ready in time")


def build_firmware_signature(firmware_hash: str) -> str:
    if not MANUFACTURER_SECRET_KEY_B64:
        raise RuntimeError("MANUFACTURER_SECRET_KEY_B64 is not set")

    secret_key = b64d(MANUFACTURER_SECRET_KEY_B64)
    signature = sign_message(
        message=firmware_hash.encode(),
        secret_key=secret_key,
        algorithm=MANUFACTURER_SIG_ALG,
    )
    return b64e(signature)


def join_device(device_id: str, device_type: str, kem: Kem, max_attempts: int = 10):
    pk, sk = kem.keypair()
    nonce_d = sha256_hex(os.urandom(16))[:16]
    join_start = time.time()

    firmware_hash = firmware_hash_for(device_id)
    firmware_signature_b64 = build_firmware_signature(firmware_hash)

    payload = {
        "device_id": device_id,
        "device_type": device_type,
        "firmware_hash": firmware_hash,
        "firmware_signature_b64": firmware_signature_b64,
        "manufacturer_sig_alg": MANUFACTURER_SIG_ALG,
        "manufacturer_public_key_b64": MANUFACTURER_PUBLIC_KEY_B64,
        "nonce_d": nonce_d,
        "kem_public_key_b64": b64e(pk),
    }

    for attempt in range(1, max_attempts + 1):
        try:
            t0 = time.perf_counter()

            r = requests.post(f"{HUB_URL}/join", json=payload, timeout=10)
            r.raise_for_status()
            data = r.json()

            t1 = time.perf_counter()
            join_latency = t1 - t0

            if not data["accepted"]:
                join_latency = time.time() - join_start

                append_csv_row(
                    JOIN_CSV,
                    [
                        "run_id",
                        "device_id",
                        "device_type",
                        "join_latency_s",
                        "join_result",
                        "sig_result",
                        "kem_alg",
                        "sig_alg",
                    ],
                    [
                        RUN_ID,
                        device_id,
                        device_type,
                        f"{join_latency:.6f}",
                        "rejected",
                        data["reason"],
                        "unknown",
                        os.getenv("MANUFACTURER_SIG_ALG", "none"),
                    ],
                )

                print(f"[{device_id}] join rejected: {data['reason']}", flush=True)
                return None

            ct = base64.b64decode(data["kem_ciphertext_b64"].encode())
            shared_secret = kem.decaps(ct, sk)

            print(
                f"[{device_id}] joined successfully | alg={data['selected_algorithm']} "
                f"| ss_len={len(shared_secret)} | session_key_hash={data['session_key_hash']}",
                flush=True
            )

            join_latency = time.time() - join_start

            append_csv_row(
                JOIN_CSV,
                [
                    "run_id",
                    "device_id",
                    "device_type",
                    "join_latency_s",
                    "join_result",
                    "sig_result",
                    "kem_alg",
                    "sig_alg",
                ],
                [
                    RUN_ID,
                    device_id,
                    device_type,
                    f"{join_latency:.6f}",
                    "accepted",
                    "valid",
                    data["selected_algorithm"],
                    os.getenv("MANUFACTURER_SIG_ALG", "none"),
                ],
            )

            print(f"[{device_id}] join_latency={join_latency:.6f}s", flush=True)

            return {
                "device_id": device_id,
                "device_type": device_type,
                "shared_secret_len": len(shared_secret),
                "blocked": False,
            }

        except requests.RequestException as exc:
            print(f"[{device_id}] join attempt {attempt}/{max_attempts} failed: {exc}", flush=True)
            time.sleep(2)

    print(f"[{device_id}] join failed after {max_attempts} attempts", flush=True)
    return None


def send_telemetry(device_id: str, metric: str, value: float):
    ts = time.time()
    payload = {
        "device_id": device_id,
        "metric": metric,
        "value": value,
        "ts": ts,
    }
    r = requests.post(f"{HUB_URL}/telemetry", json=payload, timeout=5)

    if r.status_code == 403:
        return {"blocked": True, "accepted": False, "ts": ts, "detail": r.text}

    r.raise_for_status()
    return {"blocked": False, "accepted": True, "ts": ts}


def main():
    if not MANUFACTURER_PUBLIC_KEY_B64:
        raise RuntimeError("MANUFACTURER_PUBLIC_KEY_B64 is not set")

    if not MANUFACTURER_SECRET_KEY_B64:
        raise RuntimeError("MANUFACTURER_SECRET_KEY_B64 is not set")

    ensure_experiments_dir()
    wait_for_hub()

    kem = Kem()

    device_types = ["smart_lock", "smart_bulb", "thermostat", "camera", "smart_plug"]
    joined_devices = []

    for i in range(DEVICE_COUNT):
        device_id = f"device-{i+1}"
        device_type = device_types[i % len(device_types)]
        joined = join_device(device_id, device_type, kem)
        if joined:
            joined_devices.append(joined)

    if not joined_devices:
        print("No device joined. Exiting.", flush=True)
        return

    experiments_dir = EXPERIMENTS_DIR
    experiments_dir.mkdir(parents=True, exist_ok=True)

    telemetry_csv_path = experiments_dir / "telemetry_metrics.csv"
    telemetry_file_exists = telemetry_csv_path.exists()

    telemetry_csv_file = open(telemetry_csv_path, "a", newline="")
    telemetry_writer = csv.writer(telemetry_csv_file)

    if not telemetry_file_exists:
        telemetry_writer.writerow([
            "run_id",
            "timestamp",
            "tick",
            "device_id",
            "device_type",
            "metric",
            "value",
            "blocked",
        ])

    anomaly_count = random.choice([1, 2])
    anomalous_device_ids = set(
        random.sample([d["device_id"] for d in joined_devices], anomaly_count)
    )
    anomaly_start_tick = random.randint(6, 9)

    print(
        f"Anomaly plan | devices={sorted(anomalous_device_ids)} | start_tick={anomaly_start_tick}",
        flush=True
    )

    anomaly_logged_devices = set()

    tick = 0
    while True:
        tick += 1

        for d in joined_devices:
            device_id = d["device_id"]

            if d.get("blocked"):
                continue

            is_anomalous = (
                device_id in anomalous_device_ids and tick >= anomaly_start_tick
            )

            if is_anomalous and device_id not in anomaly_logged_devices:
                anomaly_start_ts = time.time()

                append_csv_row(
                    ANOMALY_PLAN_CSV,
                    [
                        "run_id",
                        "device_id",
                        "anomaly_start_tick",
                        "anomaly_start_ts",
                    ],
                    [
                        RUN_ID,
                        device_id,
                        tick,
                        anomaly_start_ts,
                    ],
                )

                anomaly_logged_devices.add(device_id)

            if is_anomalous:
                traffic_rate = random.uniform(80.0, 100.0)
                cpu_load = random.uniform(70.0, 95.0)
                memory_usage = random.uniform(85.0, 98.0)
                temperature = random.uniform(75.0, 95.0)
                battery_level = random.uniform(5.0, 20.0)
            else:
                traffic_rate = random.uniform(10.0, 25.0)
                cpu_load = random.uniform(15.0, 45.0)
                memory_usage = random.uniform(30.0, 60.0)
                temperature = random.uniform(35.0, 55.0)
                battery_level = random.uniform(70.0, 100.0)

            metrics = [
                ("traffic_rate", traffic_rate),
                ("cpu_load", cpu_load),
                ("memory_usage", memory_usage),
                ("temperature", temperature),
            ]

            if d["device_type"] in {"smart_lock", "camera", "smart_plug"}:
                metrics.append(("battery_level", battery_level))

            try:
                blocked = False
                sent_at = time.time()

                for metric_name, metric_value in metrics:
                    result = send_telemetry(device_id, metric_name, metric_value)
                    if result["blocked"]:
                        d["blocked"] = True
                        blocked = True
                        print(f"[{device_id}] blocked by hub (quarantined or banned)", flush=True)
                        break

                if blocked:
                    continue

                for metric_name, metric_value in metrics:
                    telemetry_writer.writerow([
                        RUN_ID,
                        sent_at,
                        tick,
                        device_id,
                        d["device_type"],
                        metric_name,
                        round(metric_value, 4),
                        0,
                    ])
                telemetry_csv_file.flush()

                metrics_str = ", ".join([f"{name}={value:.2f}" for name, value in metrics])
                print(f"[{device_id}] telemetry sent: {metrics_str}", flush=True)

            except requests.RequestException as exc:
                print(f"[{device_id}] telemetry send failed: {exc}", flush=True)

        time.sleep(2)

        if not RUN_FOREVER and tick >= 10:
            break


if __name__ == "__main__":
    main()
