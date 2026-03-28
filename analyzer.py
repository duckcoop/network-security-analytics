"""
analyzer.py
Network Security Analytics Tool — main analysis pipeline.

Usage:
    python analyzer.py                        # Generates sample data and runs analysis
    python analyzer.py --input your_logs.csv  # Analyze your own log file

Output:
    - Console: threat summary report
    - sample_output/: PNG charts (traffic timeline, anomaly scatter, top IPs)
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from datetime import datetime

# ── Configuration ────────────────────────────────────────────────────────────
OUTPUT_DIR = "sample_output"
ANOMALY_THRESHOLD = -0.1        # Isolation Forest score below this = anomaly
CONTAMINATION = 0.05            # Expected fraction of anomalies in data
SUSPICIOUS_IPS = {              # Known bad IPs (threat intel feed simulation)
    "185.220.101.45", "194.165.16.78",
    "45.142.212.100", "91.108.4.0", "198.51.100.99",
}
PALETTE = {
    "normal": "#4A90D9",
    "anomaly": "#E8333A",
    "highlight": "#F5A623",
    "bg": "#F8F9FA",
    "grid": "#E0E0E0",
}


# ── Isolation Forest (pure NumPy implementation) ─────────────────────────────
class IsolationTree:
    """Single tree in an Isolation Forest."""

    def __init__(self, max_depth):
        self.max_depth = max_depth
        self.split_feature = None
        self.split_value = None
        self.left = None
        self.right = None
        self.size = 0
        self.is_leaf = False

    def fit(self, X, depth=0):
        self.size = len(X)
        if depth >= self.max_depth or self.size <= 1:
            self.is_leaf = True
            return self

        n_features = X.shape[1]
        self.split_feature = np.random.randint(0, n_features)
        col = X[:, self.split_feature]
        col_min, col_max = col.min(), col.max()

        if col_min == col_max:
            self.is_leaf = True
            return self

        self.split_value = np.random.uniform(col_min, col_max)
        left_mask = col < self.split_value
        self.left = IsolationTree(self.max_depth).fit(X[left_mask], depth + 1)
        self.right = IsolationTree(self.max_depth).fit(X[~left_mask], depth + 1)
        return self

    def path_length(self, x, depth=0):
        if self.is_leaf:
            return depth + _c(self.size)
        if x[self.split_feature] < self.split_value:
            return self.left.path_length(x, depth + 1)
        return self.right.path_length(x, depth + 1)


def _c(n):
    """Average path length of an unsuccessful BST search."""
    if n <= 1:
        return 0
    return 2 * (np.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)


class IsolationForest:
    """
    Unsupervised anomaly detection via Isolation Forest.
    Points that are easier to isolate (shorter average path) are more anomalous.
    """

    def __init__(self, n_estimators=100, max_samples=256, contamination=0.05, random_state=42):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.trees = []
        self.threshold_ = None

    def fit(self, X):
        np.random.seed(self.random_state)
        self.trees = []
        max_depth = int(np.ceil(np.log2(self.max_samples)))
        for _ in range(self.n_estimators):
            n = min(self.max_samples, len(X))
            idx = np.random.choice(len(X), n, replace=False)
            tree = IsolationTree(max_depth).fit(X[idx])
            self.trees.append(tree)

        scores = self._raw_scores(X)
        self.threshold_ = np.percentile(scores, 100 * (1 - self.contamination))
        return self

    def _raw_scores(self, X):
        n = len(X)
        depths = np.array([[t.path_length(x) for t in self.trees] for x in X])
        avg_depths = depths.mean(axis=1)
        c_n = _c(min(self.max_samples, n))
        return -2 ** (-avg_depths / c_n)  # Negative so lower = more anomalous

    def decision_function(self, X):
        return self._raw_scores(X)

    def predict(self, X):
        scores = self._raw_scores(X)
        return np.where(scores < self.threshold_, -1, 1)  # -1 = anomaly, 1 = normal


# ── Data Loading & Cleaning ───────────────────────────────────────────────────
def load_logs(path):
    """Load and clean log CSV. Generates sample data if path not found."""
    if not os.path.exists(path):
        print(f"  '{path}' not found — generating sample data...")
        from log_generator import generate_logs
        df = generate_logs(n_records=1000)
        df.to_csv(path, index=False)
        print(f"  Generated {len(df)} records and saved to {path}\n")
    else:
        df = pd.read_csv(path)

    # Parse and validate
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip", "dest_ip"])
    df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce").fillna(0)
    df["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").fillna(0).astype(int)
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


# ── Feature Engineering ────────────────────────────────────────────────────────
def engineer_features(df):
    """Extract numeric features for anomaly detection."""
    features = pd.DataFrame()
    features["log_bytes"] = np.log1p(df["bytes_transferred"])
    features["dest_port"] = df["dest_port"].astype(float)
    features["hour"] = df["timestamp"].dt.hour.astype(float)
    features["is_suspicious_dest"] = df["dest_ip"].isin(SUSPICIOUS_IPS).astype(float)
    features["is_deny"] = (df.get("status", "ALLOW") == "DENY").astype(float)
    features["is_high_port"] = (df["dest_port"] > 1024).astype(float)
    return features.values.astype(np.float64)


# ── Anomaly Detection ──────────────────────────────────────────────────────────
def detect_anomalies(df, contamination=CONTAMINATION):
    """Run Isolation Forest and attach scores/labels to dataframe."""
    print("  Running Isolation Forest anomaly detection...")
    X = engineer_features(df)

    model = IsolationForest(n_estimators=100, max_samples=256,
                            contamination=contamination, random_state=42)
    model.fit(X)

    df = df.copy()
    df["anomaly_score"] = model.decision_function(X)
    df["is_anomaly"] = (model.predict(X) == -1)
    return df


# ── Visualizations ─────────────────────────────────────────────────────────────
def plot_traffic_timeline(df, output_dir):
    """Line chart of hourly traffic volume with anomaly events marked."""
    fig, ax = plt.subplots(figsize=(14, 5), facecolor=PALETTE["bg"])
    ax.set_facecolor(PALETTE["bg"])

    hourly = df.set_index("timestamp").resample("H")["bytes_transferred"].sum() / 1e6
    ax.fill_between(hourly.index, hourly.values, alpha=0.25, color=PALETTE["normal"])
    ax.plot(hourly.index, hourly.values, color=PALETTE["normal"], linewidth=1.5, label="Traffic (MB/hr)")

    # Mark anomaly events
    anomalies = df[df["is_anomaly"]]
    if not anomalies.empty:
        hourly_anom = anomalies.set_index("timestamp").resample("H").size()
        for ts, count in hourly_anom.items():
            if count > 0 and ts in hourly.index:
                ax.axvline(x=ts, color=PALETTE["anomaly"], alpha=0.4, linewidth=1)
        ax.scatter([], [], color=PALETTE["anomaly"], marker="|", s=80,
                   label=f"Anomaly hours ({len(anomalies)} events)")

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.WeekdayLocator(interval=1))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.set_xlabel("Date", fontsize=11)
    ax.set_ylabel("Data Transferred (MB)", fontsize=11)
    ax.set_title("Network Traffic Volume — 30 Day Window", fontsize=14, fontweight="bold", pad=15)
    ax.legend(framealpha=0.8)
    ax.grid(axis="y", color=PALETTE["grid"], linewidth=0.7)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    path = os.path.join(output_dir, "traffic_over_time.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")


def plot_anomaly_scatter(df, output_dir):
    """Scatter plot: bytes vs port, colored by anomaly score."""
    fig, ax = plt.subplots(figsize=(10, 6), facecolor=PALETTE["bg"])
    ax.set_facecolor(PALETTE["bg"])

    normal = df[~df["is_anomaly"]]
    anomalies = df[df["is_anomaly"]]

    ax.scatter(normal["dest_port"], np.log1p(normal["bytes_transferred"]),
               c=PALETTE["normal"], alpha=0.3, s=18, label="Normal", zorder=2)
    ax.scatter(anomalies["dest_port"], np.log1p(anomalies["bytes_transferred"]),
               c=PALETTE["anomaly"], alpha=0.75, s=45, label=f"Anomaly ({len(anomalies)})",
               edgecolors="white", linewidth=0.4, zorder=3)

    # Annotate top outliers
    top_outliers = anomalies.nsmallest(5, "anomaly_score")
    for _, row in top_outliers.iterrows():
        ax.annotate(row["dest_ip"], xy=(row["dest_port"], np.log1p(row["bytes_transferred"])),
                    fontsize=7, color="#8B0000", xytext=(8, 4), textcoords="offset points",
                    arrowprops=dict(arrowstyle="-", color="#8B0000", lw=0.8))

    ax.set_xlabel("Destination Port", fontsize=11)
    ax.set_ylabel("Bytes Transferred (log scale)", fontsize=11)
    ax.set_title("Anomaly Detection — Bytes vs Port", fontsize=14, fontweight="bold", pad=15)
    ax.legend(framealpha=0.8, loc="upper right")
    ax.grid(color=PALETTE["grid"], linewidth=0.6, alpha=0.7)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    path = os.path.join(output_dir, "anomaly_scatter.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")


def plot_top_ips(df, output_dir, n=15):
    """Bar chart of top source IPs by total bytes, suspicious ones flagged."""
    top = (df.groupby("dest_ip")["bytes_transferred"]
             .sum()
             .nlargest(n)
             .reset_index())
    top["is_suspicious"] = top["dest_ip"].isin(SUSPICIOUS_IPS)
    top["color"] = top["is_suspicious"].map({True: PALETTE["anomaly"], False: PALETTE["normal"]})
    top["label"] = top["dest_ip"] + top["is_suspicious"].map({True: " ⚠", False: ""})

    fig, ax = plt.subplots(figsize=(12, 6), facecolor=PALETTE["bg"])
    ax.set_facecolor(PALETTE["bg"])

    bars = ax.barh(top["label"], top["bytes_transferred"] / 1e6,
                   color=top["color"], edgecolor="white", linewidth=0.4)

    for bar, (_, row) in zip(bars, top.iterrows()):
        if row["is_suspicious"]:
            ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                    "FLAGGED", va="center", fontsize=8, color=PALETTE["anomaly"],
                    fontweight="bold")

    ax.set_xlabel("Total Data Transferred (MB)", fontsize=11)
    ax.set_title(f"Top {n} Destination IPs by Traffic Volume", fontsize=14, fontweight="bold", pad=15)
    ax.grid(axis="x", color=PALETTE["grid"], linewidth=0.6)
    ax.spines[["top", "right"]].set_visible(False)
    ax.invert_yaxis()

    from matplotlib.patches import Patch
    legend_elements = [Patch(facecolor=PALETTE["normal"], label="Normal"),
                       Patch(facecolor=PALETTE["anomaly"], label="Suspicious / Flagged")]
    ax.legend(handles=legend_elements, loc="lower right", framealpha=0.8)

    plt.tight_layout()
    path = os.path.join(output_dir, "top_source_ips.png")
    plt.savefig(path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Saved: {path}")


# ── Console Report ─────────────────────────────────────────────────────────────
def print_report(df):
    """Print a threat intelligence summary to the console."""
    anomalies = df[df["is_anomaly"]]
    sep = "─" * 60

    print(f"\n{sep}")
    print("  NETWORK SECURITY ANALYTICS — THREAT SUMMARY")
    print(sep)
    print(f"  Analysis window : {df['timestamp'].min().date()} → {df['timestamp'].max().date()}")
    print(f"  Total events    : {len(df):,}")
    print(f"  Anomalies found : {len(anomalies):,} ({100*len(anomalies)/len(df):.1f}%)")
    print(f"  Total traffic   : {df['bytes_transferred'].sum()/1e9:.2f} GB")

    print(f"\n  TOP ANOMALOUS EVENTS (by isolation score)")
    print(f"  {'Source IP':<18} {'Dest IP':<20} {'Port':<8} {'Bytes':>12} {'Score':>8}")
    print(f"  {'─'*18} {'─'*20} {'─'*8} {'─'*12} {'─'*8}")
    for _, row in anomalies.nsmallest(8, "anomaly_score").iterrows():
        flagged = " ⚠" if row["dest_ip"] in SUSPICIOUS_IPS else ""
        print(f"  {row['source_ip']:<18} {row['dest_ip']+flagged:<20} "
              f"{row['dest_port']:<8} {row['bytes_transferred']:>12,} {row['anomaly_score']:>8.3f}")

    suspicious_hits = anomalies[anomalies["dest_ip"].isin(SUSPICIOUS_IPS)]
    if not suspicious_hits.empty:
        print(f"\n  ⚠  THREAT INTEL MATCHES: {len(suspicious_hits)} events to known-bad IPs")
        for ip in suspicious_hits["dest_ip"].unique():
            count = (suspicious_hits["dest_ip"] == ip).sum()
            total_bytes = suspicious_hits[suspicious_hits["dest_ip"] == ip]["bytes_transferred"].sum()
            print(f"     {ip:<20} {count} events | {total_bytes/1e6:.1f} MB transferred")

    print(f"\n  Charts saved to ./{OUTPUT_DIR}/")
    print(sep + "\n")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Network Security Analytics Tool")
    parser.add_argument("--input", default="sample_logs.csv", help="Path to log CSV file")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help="Expected anomaly rate (default: 0.05)")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("\n Network Security Analytics Tool")
    print(" ─────────────────────────────────")

    print("\n[1/4] Loading logs...")
    df = load_logs(args.input)
    print(f"  Loaded {len(df):,} records")

    print("\n[2/4] Detecting anomalies...")
    df = detect_anomalies(df, contamination=args.contamination)

    print("\n[3/4] Generating charts...")
    plot_traffic_timeline(df, OUTPUT_DIR)
    plot_anomaly_scatter(df, OUTPUT_DIR)
    plot_top_ips(df, OUTPUT_DIR)

    print("\n[4/4] Threat summary:")
    print_report(df)


if __name__ == "__main__":
    main()
