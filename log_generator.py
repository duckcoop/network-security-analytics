"""
log_generator.py
Generates realistic synthetic network traffic logs for demo/testing purposes.
Injects ~4% anomalous entries (port scans, data exfiltration attempts, known bad IPs).
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random

# Seed for reproducibility
random.seed(42)
np.random.seed(42)

# Known suspicious IPs (simulated threat intelligence)
SUSPICIOUS_IPS = [
    "185.220.101.45",  # Known Tor exit node
    "194.165.16.78",   # Flagged C2 server
    "45.142.212.100",  # Reported scanner
    "91.108.4.0",      # Suspicious ASN
    "198.51.100.99",   # TEST-NET (RFC 5737)
]

INTERNAL_IPS = [f"192.168.1.{i}" for i in range(2, 50)]
EXTERNAL_IPS = [f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(80)]
ALL_EXTERNAL = EXTERNAL_IPS + SUSPICIOUS_IPS

PROTOCOLS = ["TCP", "UDP", "ICMP", "DNS", "HTTPS", "HTTP"]
COMMON_PORTS = [80, 443, 22, 53, 8080, 8443, 3389, 445, 25, 110, 993, 3306]
SCAN_PORTS = list(range(1, 1024))  # Full range for port scan simulation

STATUS_CODES = ["ALLOW", "ALLOW", "ALLOW", "ALLOW", "DENY", "DENY"]


def generate_normal_entry(timestamp):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(ALL_EXTERNAL[:80])  # Normal traffic goes to normal IPs
    port = random.choice(COMMON_PORTS)
    protocol = random.choice(PROTOCOLS[:4])
    # Normal bytes: 200 bytes to 5MB, log-normal distribution
    bytes_transferred = int(np.random.lognormal(mean=8, sigma=2))
    bytes_transferred = max(64, min(bytes_transferred, 5_000_000))
    status = random.choice(STATUS_CODES)
    return {
        "timestamp": timestamp,
        "source_ip": src,
        "dest_ip": dst,
        "dest_port": port,
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "status": status,
        "anomaly": 0
    }


def generate_anomalous_entry(timestamp, anomaly_type="exfil"):
    src = random.choice(INTERNAL_IPS)

    if anomaly_type == "exfil":
        # Data exfiltration: large outbound transfer to suspicious IP
        dst = random.choice(SUSPICIOUS_IPS)
        port = random.choice([443, 80, 4444, 8888])
        protocol = "TCP"
        bytes_transferred = random.randint(50_000_000, 500_000_000)  # 50MB-500MB
        status = "ALLOW"

    elif anomaly_type == "scan":
        # Port scan: many connections, tiny packets, sequential ports
        dst = random.choice(EXTERNAL_IPS[:20])
        port = random.choice(SCAN_PORTS)
        protocol = "TCP"
        bytes_transferred = random.randint(40, 120)  # Tiny SYN packets
        status = random.choice(["DENY", "ALLOW"])

    elif anomaly_type == "c2":
        # C2 beacon: periodic connection to known bad IP
        dst = random.choice(SUSPICIOUS_IPS)
        port = random.choice([4444, 8080, 1337, 31337])
        protocol = random.choice(["TCP", "UDP"])
        bytes_transferred = random.randint(200, 2000)  # Small beacon
        status = "ALLOW"

    else:
        return generate_normal_entry(timestamp)

    return {
        "timestamp": timestamp,
        "source_ip": src,
        "dest_ip": dst,
        "dest_port": port,
        "protocol": protocol,
        "bytes_transferred": bytes_transferred,
        "status": status,
        "anomaly": 1
    }


def generate_logs(n_records=1000, start_date=None, anomaly_rate=0.04):
    """
    Generate n_records of synthetic network log data.

    Args:
        n_records: Total number of log entries to generate
        start_date: Start datetime (defaults to 30 days ago)
        anomaly_rate: Fraction of records that are anomalous

    Returns:
        pd.DataFrame with network log data
    """
    if start_date is None:
        start_date = datetime.now() - timedelta(days=30)

    records = []
    n_anomalies = int(n_records * anomaly_rate)
    anomaly_indices = set(random.sample(range(n_records), n_anomalies))
    anomaly_types = ["exfil", "scan", "c2"]

    for i in range(n_records):
        # Distribute timestamps across the time range with realistic traffic spikes
        hour_offset = random.gauss(mu=14 * 3600, sigma=6 * 3600)  # Peak at 2pm
        hour_offset = max(0, min(hour_offset, 30 * 24 * 3600))
        ts = start_date + timedelta(seconds=hour_offset + random.randint(-300, 300))

        if i in anomaly_indices:
            atype = random.choice(anomaly_types)
            records.append(generate_anomalous_entry(ts, anomaly_type=atype))
        else:
            records.append(generate_normal_entry(ts))

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    return df


if __name__ == "__main__":
    print("Generating 1,000 synthetic network log entries...")
    df = generate_logs(n_records=1000)
    output_path = "sample_logs.csv"
    df.to_csv(output_path, index=False)
    print(f"Saved {len(df)} records to {output_path}")
    print(f"  Normal entries:    {(df['anomaly'] == 0).sum()}")
    print(f"  Anomalous entries: {(df['anomaly'] == 1).sum()}")
    print(f"  Date range: {df['timestamp'].min().date()} to {df['timestamp'].max().date()}")
