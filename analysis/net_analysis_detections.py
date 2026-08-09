import pandas as pd


def detect_port_scan(net_data, min_unique_ports=10, window_minutes=5):
    """Identifies a single source IP contacting many destination ports on a target host in a short window."""
    if (
        net_data.empty
        or "src_ip" not in net_data.columns
        or "dest_ip" not in net_data.columns
        or "dest_port" not in net_data.columns
    ):
        return pd.DataFrame()

    work_data = net_data.dropna(subset=["src_ip", "dest_ip", "dest_port"]).copy()
    if work_data.empty:
        return pd.DataFrame()

    summary = (
        work_data.groupby(["src_ip", "dest_ip"])
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            unique_ports=("dest_port", "nunique"),
        )
        .reset_index()
    )

    summary["window_duration"] = summary["last_seen"] - summary["first_seen"]

    scans = summary[
        (summary["unique_ports"] >= min_unique_ports)
        & (summary["window_duration"] <= pd.Timedelta(minutes=window_minutes))
    ].copy()

    return scans


def detect_net_multihost_targeting(net_data, min_unique_hosts=3, window_minutes=15):
    """Identifies a single source IP contacting the same service/port across multiple hosts."""
    if (
        net_data.empty
        or "src_ip" not in net_data.columns
        or "dest_ip" not in net_data.columns
        or "dest_port" not in net_data.columns
    ):
        return pd.DataFrame()

    work_data = net_data.dropna(subset=["src_ip", "dest_ip", "dest_port"]).copy()
    if work_data.empty:
        return pd.DataFrame()

    summary = (
        work_data.groupby(["src_ip", "dest_port"])
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            unique_hosts=("dest_ip", "nunique"),
            targeted_hosts=("dest_ip", lambda x: list(x.unique())),
        )
        .reset_index()
    )

    summary["window_duration"] = summary["last_seen"] - summary["first_seen"]

    multi_host = summary[
        (summary["unique_hosts"] >= min_unique_hosts)
        & (summary["window_duration"] <= pd.Timedelta(minutes=window_minutes))
    ].copy()

    return multi_host


def detect_large_outbound_transfer(net_data, byte_threshold_bytes=8_000_000):
    """Identifies internal hosts sending outbound volume (bytes_toserver) exceeding a defined byte threshold."""
    if net_data.empty or "src_ip" not in net_data.columns or "dest_ip" not in net_data.columns:
        return pd.DataFrame()

    work_data = net_data.copy()

    if "flow" in work_data.columns:
        def extract_outbound_bytes(val):
            if isinstance(val, dict):
                return val.get("bytes_toserver", 0)
            return 0

        work_data["total_bytes"] = work_data["flow"].apply(extract_outbound_bytes)
    elif "bytes" in work_data.columns:
        work_data["total_bytes"] = pd.to_numeric(work_data["bytes"], errors="coerce").fillna(0)
    else:
        return pd.DataFrame()

    transfers = (
        work_data.groupby(["src_ip", "dest_ip"])
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            total_bytes_sent=("total_bytes", "sum"),
        )
        .reset_index()
    )

    large_transfers = transfers[
        transfers["total_bytes_sent"] >= byte_threshold_bytes
    ].copy()

    return large_transfers


def detect_suricata_alerts(net_data):
    """Filters native sensor-generated alert records."""
    if net_data.empty or "event_type" not in net_data.columns:
        return pd.DataFrame()

    alerts = net_data[net_data["event_type"] == "alert"].copy()
    if alerts.empty:
        return pd.DataFrame()

    if "alert" in alerts.columns:
        alerts["signature"] = alerts["alert"].apply(
            lambda x: x.get("signature", "Unknown Alert") if isinstance(x, dict) else str(x)
        )
        alerts["category"] = alerts["alert"].apply(
            lambda x: x.get("category", "") if isinstance(x, dict) else ""
        )

    cols = [
        c
        for c in [
            "timestamp",
            "host",
            "src_ip",
            "dest_ip",
            "dest_port",
            "signature",
            "category",
        ]
        if c in alerts.columns
    ]

    return alerts[cols].copy()