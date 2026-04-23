import json
from pathlib import Path

import pandas as pd


BASE = Path(__file__).parent

join_file = BASE / "join_metrics.csv"
detect_file = BASE / "detection_metrics.csv"
anomaly_file = BASE / "anomaly_events.csv"
ledger_file = BASE / "ledger_events.json"

out_csv = BASE / "results_table.csv"
out_txt = BASE / "results_summary.txt"


def safe_float_series(series):
    return pd.to_numeric(series, errors="coerce").dropna()


def main():
    join_df = pd.read_csv(join_file)
    detect_df = pd.read_csv(detect_file)
    anomaly_df = pd.read_csv(anomaly_file)

    with open(ledger_file, "r") as f:
        ledger_events = json.load(f)

    # ---- Join metrics ----
    join_lat = safe_float_series(join_df["join_latency_s"])
    num_runs = join_df["run_id"].nunique()
    joined_devices = len(join_df)

    mean_join = join_lat.mean() if not join_lat.empty else None
    median_join = join_lat.median() if not join_lat.empty else None
    min_join = join_lat.min() if not join_lat.empty else None
    max_join = join_lat.max() if not join_lat.empty else None

    # ---- Detection metrics ----
    detection_records = len(detect_df)

    quarantines = detect_df[detect_df["decision"] == "quarantine"].copy()
    quarantine_actions = int((quarantines["action_sent"] == 1).sum())

    quarantined_devices = set(quarantines["device_id"].dropna().tolist())

    # ---- Device triggered at least ones ----
    triggered = detect_df[detect_df["trigger_metric"].fillna("") != ""].copy()

    trigger_avg = safe_float_series(triggered["trigger_avg"])
    trigger_threshold = safe_float_series(triggered["trigger_threshold"])

    mean_trigger_avg = trigger_avg.mean() if not trigger_avg.empty else None
    mean_trigger_thr = trigger_threshold.mean() if not trigger_threshold.empty else None

    # ---- Detection delay metrics (seconds) ----
    detection_delay_series = pd.Series(dtype=float)

    if not anomaly_df.empty:
        q_ts = detect_df[detect_df["decision"] == "quarantine"].copy()

        if not q_ts.empty:
            q_ts["timestamp"] = pd.to_numeric(q_ts["timestamp"], errors="coerce")
            anomaly_df["anomaly_start_ts"] = pd.to_numeric(
                anomaly_df["anomaly_start_ts"], errors="coerce"
            )

            first_q = (
                q_ts.groupby(["run_id", "device_id"], as_index=False)["timestamp"]
                .min()
                .rename(columns={"timestamp": "first_quarantine_ts"})
            )

            delay_df = anomaly_df.merge(first_q, on=["run_id", "device_id"], how="left")
            delay_df["detection_delay_s"] = (
                delay_df["first_quarantine_ts"] - delay_df["anomaly_start_ts"]
            )

            detection_delay_series = pd.to_numeric(
                delay_df["detection_delay_s"], errors="coerce"
            ).dropna()

    mean_detection_delay = (
        detection_delay_series.mean() if not detection_delay_series.empty else None
    )
    median_detection_delay = (
        detection_delay_series.median() if not detection_delay_series.empty else None
    )
    min_detection_delay = (
        detection_delay_series.min() if not detection_delay_series.empty else None
    )
    max_detection_delay = (
        detection_delay_series.max() if not detection_delay_series.empty else None
    )

    # ---- False positives assumptions ----
    false_positives = int(
        len(quarantines[quarantines["trigger_metric"].fillna("") == ""])
    )

    # ---- Telemetry metrics ----
    telemetry_records = sum(1 for _ in open(BASE / "telemetry_metrics.csv")) - 1

    # ---- Ledger metrics ----
    ledger_event_count = len(ledger_events)

    event_type_counts = {}
    for ev in ledger_events:
        et = ev.get("event_type", "unknown")
        event_type_counts[et] = event_type_counts.get(et, 0) + 1

    # ---- Table rows ----
    """
    rows = [
        ("Number of runs", num_runs, "Experimental repetitions"),
        ("Joined devices", joined_devices, "Total successful PQC onboarding events"),
        ("Mean join latency (s)", round(mean_join, 6) if mean_join is not None else "", "Average onboarding cost"),
        ("Median join latency (s)", round(median_join, 6) if median_join is not None else "", "Median onboarding cost"),
        ("Min join latency (s)", round(min_join, 6) if min_join is not None else "", "Fastest onboarding"),
        ("Max join latency (s)", round(max_join, 6) if max_join is not None else "", "Slowest onboarding"),
        ("Total telemetry records", telemetry_records, "Runtime telemetry dataset size"),
        ("Total detection records", detection_records, "AI monitor evaluation samples"),
        ("Quarantine actions", quarantine_actions, "Total quarantine decisions enforced"),
        ("False positives", false_positives, "Benign devices incorrectly quarantined"),
        ("Mean trigger value", round(mean_trigger_avg, 4) if mean_trigger_avg is not None else "", "Average trigger metric value at detection"),
        ("Mean trigger threshold", round(mean_trigger_thr, 4) if mean_trigger_thr is not None else "", "Average configured threshold"),
        ("Ledger events", ledger_event_count, "Audit trail size"),
    ]
    """
    rows = [
        ("Number of runs", num_runs, "Experimental repetitions"),
        ("Joined devices", joined_devices, "Total successful PQC onboarding events"),
        ("Mean join latency (s)", round(mean_join, 6) if mean_join is not None else "", "Average onboarding cost"),
        ("Median join latency (s)", round(median_join, 6) if median_join is not None else "", "Median onboarding cost"),
        ("Min join latency (s)", round(min_join, 6) if min_join is not None else "", "Fastest onboarding"),
        ("Max join latency (s)", round(max_join, 6) if max_join is not None else "", "Slowest onboarding"),
        ("Total telemetry records", telemetry_records, "Runtime telemetry dataset size"),
        ("Total detection records", detection_records, "AI monitor evaluation samples"),
        ("Quarantine actions", quarantine_actions, "Total quarantine decisions enforced"),
        ("Mean trigger value", round(mean_trigger_avg, 4) if mean_trigger_avg is not None else "", "Average trigger metric value at detection"),
        ("Mean trigger threshold", round(mean_trigger_thr, 4) if mean_trigger_thr is not None else "", "Average configured threshold"),
        #("Mean detection delay (cycles)", round(mean_detection_delay, 4) if mean_detection_delay is not None else "", "Average delay between anomaly injection and first quarantine"),
        #("Median detection delay (cycles)", round(median_detection_delay, 4) if median_detection_delay is not None else "", "Median delay between anomaly injection and first quarantine"),
        #("Min detection delay (cycles)", round(min_detection_delay, 4) if min_detection_delay is not None else "", "Fastest anomaly detection delay"),
        #("Max detection delay (cycles)", round(max_detection_delay, 4) if max_detection_delay is not None else "", "Slowest anomaly detection delay"),
        ("Mean detection delay (s)", round(mean_detection_delay, 4) if mean_detection_delay is not None else "", "Average delay between anomaly injection and first quarantine"),
        ("Median detection delay (s)", round(median_detection_delay, 4) if median_detection_delay is not None else "", "Median delay between anomaly injection and first quarantine"),
        ("Min detection delay (s)", round(min_detection_delay, 4) if min_detection_delay is not None else "", "Fastest anomaly detection delay"),
        ("Max detection delay (s)", round(max_detection_delay, 4) if max_detection_delay is not None else "", "Slowest anomaly detection delay"),
    ]


    table_df = pd.DataFrame(rows, columns=["Metric", "Value", "Meaning"])
    table_df.to_csv(out_csv, index=False)

    with open(out_txt, "w") as f:
        f.write("Experimental results summary\n")
        f.write("============================\n\n")
        for metric, value, meaning in rows:
            f.write(f"{metric}: {value} ({meaning})\n")

        f.write("\nLedger event type counts\n")
        f.write("------------------------\n")
        for k, v in sorted(event_type_counts.items()):
            f.write(f"{k}: {v}\n")

    print(f"Saved: {out_csv}")
    print(f"Saved: {out_txt}")


if __name__ == "__main__":
    main()
