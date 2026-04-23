import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


BASE = Path(__file__).parent
PLOTS = BASE / "plots"
PLOTS.mkdir(exist_ok=True)

join_file = BASE / "join_metrics.csv"
telemetry_file = BASE / "telemetry_metrics.csv"
detect_file = BASE / "detection_metrics.csv"


def plot_join_latency():
    df = pd.read_csv(join_file)

    if df.empty:
        print("join_metrics.csv is empty")
        return

    lat = pd.to_numeric(df["join_latency_s"], errors="coerce").dropna()

    if lat.empty:
        print("No valid join latency values found")
        return

    plt.figure(figsize=(7, 5))
    plt.hist(lat, bins=min(12, max(4, len(lat) // 10 if len(lat) > 20 else 10)))
    plt.xlabel("Join latency (seconds)")
    plt.ylabel("Count")
    plt.title("PQC Device Join Latency Distribution")
    plt.tight_layout()
    plt.savefig(PLOTS / "fig_join_latency.png", dpi=300)
    plt.close()


def plot_telemetry_representative_run():
    df = pd.read_csv(telemetry_file)
    detect_df = pd.read_csv(detect_file)

    if df.empty:
        print("telemetry_metrics.csv is empty")
        return

    traffic = df[df["metric"] == "traffic_rate"].copy()

    if traffic.empty:
        print("No traffic_rate samples found in telemetry_metrics.csv")
        return

    traffic["tick"] = pd.to_numeric(traffic["tick"], errors="coerce")
    traffic["value"] = pd.to_numeric(traffic["value"], errors="coerce")
    traffic = traffic.dropna(subset=["tick", "value"])

    # Preferiamo una run che abbia almeno una quarantena
    quarantine_runs = (
        detect_df[detect_df["decision"] == "quarantine"]["run_id"]
        .dropna()
        .unique()
        .tolist()
    )

    if quarantine_runs:
        selected_run = sorted(quarantine_runs)[0]
    else:
        candidate_runs = (
            traffic.groupby("run_id")["value"]
            .max()
            .sort_index()
        )
        anomalous_runs = candidate_runs[candidate_runs > 70]

        if not anomalous_runs.empty:
            selected_run = anomalous_runs.index[0]
        else:
            selected_run = sorted(traffic["run_id"].unique())[0]

    subrun = traffic[traffic["run_id"] == selected_run].copy()

    plt.figure(figsize=(9, 5))

    for dev in sorted(subrun["device_id"].unique()):
        sub = subrun[subrun["device_id"] == dev].sort_values("tick")
        plt.plot(sub["tick"], sub["value"], marker="o", linewidth=2, label=dev)

    plt.axhline(70, linestyle="--", color="red", label="Anomaly threshold")
    plt.xlim(1, 10)
    plt.xticks(range(1, 11))
    plt.xlabel("Tick")
    plt.ylabel("Traffic rate")
    plt.title(f"Representative Telemetry Behaviour ({selected_run})")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS / "fig_telemetry_representative_run.png", dpi=300)
    plt.close()


def plot_telemetry_mean_across_runs():
    df = pd.read_csv(telemetry_file)

    if df.empty:
        print("telemetry_metrics.csv is empty")
        return

    traffic = df[df["metric"] == "traffic_rate"].copy()

    if traffic.empty:
        print("No traffic_rate samples found in telemetry_metrics.csv")
        return

    traffic["tick"] = pd.to_numeric(traffic["tick"], errors="coerce")
    traffic["value"] = pd.to_numeric(traffic["value"], errors="coerce")
    traffic = traffic.dropna(subset=["tick", "value"])

    grouped = (
        traffic.groupby(["tick", "device_id"], as_index=False)["value"]
        .mean()
        .rename(columns={"value": "mean_value"})
    )

    plt.figure(figsize=(9, 5))

    for dev in sorted(grouped["device_id"].unique()):
        sub = grouped[grouped["device_id"] == dev].sort_values("tick")
        plt.plot(sub["tick"], sub["mean_value"], marker="o", linewidth=2, label=dev)

    plt.axhline(70, linestyle="--", color="red", label="Anomaly threshold")
    plt.xlim(1, 10)
    plt.xticks(range(1, 11))
    plt.xlabel("Tick")
    plt.ylabel("Mean traffic rate across runs")
    plt.title("Average Telemetry Behaviour Across 100 Runs")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS / "fig_telemetry_mean_across_runs.png", dpi=300)
    plt.close()


def plot_detection_trigger():
    df = pd.read_csv(detect_file)

    if df.empty:
        print("detection_metrics.csv is empty")
        return

    trig = df.copy()
    trig["trigger_avg"] = pd.to_numeric(trig["trigger_avg"], errors="coerce")
    trig["trigger_threshold"] = pd.to_numeric(trig["trigger_threshold"], errors="coerce")
    trig = trig.dropna(subset=["trigger_avg"])

    if trig.empty:
        print("No trigger_avg values found in detection_metrics.csv")
        return

    trig["run_num"] = trig["run_id"].str.replace("run_", "", regex=False).astype(int)

    plt.figure(figsize=(13, 5))

    for dev in sorted(trig["device_id"].unique()):
        sub = trig[trig["device_id"] == dev]

        plt.scatter(
            sub["run_num"],
            sub["trigger_avg"],
            s=22,
            alpha=0.7,
            label=dev
        )

    thr = trig["trigger_threshold"].dropna()
    if not thr.empty:
        plt.axhline(
            thr.iloc[0],
            linestyle="--",
            color="red",
            label="Detection threshold"
        )

    plt.xlim(1, trig["run_num"].max())
    plt.xticks(range(1, int(trig["run_num"].max()) + 1, 10))
    plt.xlabel("Run")
    plt.ylabel("Trigger metric moving average")
    plt.title("Detection Trigger Value vs Threshold")
    plt.legend()
    plt.tight_layout()
    plt.savefig(PLOTS / "fig_detection_trigger.png", dpi=300)
    plt.close()


def main():
    plot_join_latency()
    plot_telemetry_representative_run()
    plot_telemetry_mean_across_runs()
    plot_detection_trigger()
    print("Plots generated in experiments/plots/")


if __name__ == "__main__":
    main()
