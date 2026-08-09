import pandas as pd


def detect_ss_brute_force(auth_data):
    threshold_attempts = 4
    window_minutes = 4

    work_data = auth_data.copy()

    # Include both standard failures and invalid username attempts
    failed = (
        work_data[
            (work_data["auth_service"] == "sshd")
            & (work_data["event_type"] == "password_auth")
            & (work_data["outcome"].isin(["failed", "failed_invalid_user"]))
        ]
        .sort_values(["host", "src_ip", "username", "timestamp"])
    )

    if failed.empty:
        return pd.DataFrame()

    failed["window_start"] = (
        failed.groupby(["host", "src_ip", "username"])["timestamp"]
        .shift(threshold_attempts - 1)
    )
    failed["time_delta"] = failed["timestamp"] - failed["window_start"]

    max_duration = pd.Timedelta(minutes=window_minutes)
    matches = failed[failed["time_delta"] <= max_duration]

    if matches.empty:
        return pd.DataFrame()

    flagged_keys = matches[["host", "src_ip", "username"]].drop_duplicates()
    incident_log = failed.merge(flagged_keys, on=["host", "src_ip", "username"])

    summary = (
        incident_log.groupby(["host", "src_ip", "username"])
        .agg(
            first_seen=("window_start", "min"),
            last_seen=("timestamp", "max"),
            failed_count=("timestamp", "count"),
        )
        .reset_index()
    )
    summary["detection_type"] = "Single-Source Brute Force (T1110.001)"

    return summary


def detect_credential_spray(
    auth_data,
    min_unique_users=5,
    max_attempts_per_user=2,
    window_hours=24,
):
    failed = auth_data[
        auth_data["outcome"].isin(["failed", "failed_invalid_user"])
    ].copy()

    if failed.empty:
        return pd.DataFrame()

    user_counts = (
        failed.groupby(["src_ip", "username"])
        .size()
        .reset_index(name="user_attempts")
    )

    max_attempts_df = (
        user_counts.groupby("src_ip")
        .agg(
            max_attempts_per_user=("user_attempts", "max"),
            unique_users=("username", "nunique"),
        )
        .reset_index()
    )

    summary = (
        failed.groupby("src_ip")
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            total_failed=("timestamp", "count"),
            targeted_users=("username", lambda x: list(x.unique())),
            targeted_hosts=("host", lambda x: list(x.unique())),
        )
        .reset_index()
    )

    summary = summary.merge(max_attempts_df, on="src_ip")
    summary["window_duration"] = summary["last_seen"] - summary["first_seen"]

    sprays = summary[
        (summary["unique_users"] >= min_unique_users)
        & (summary["max_attempts_per_user"] <= max_attempts_per_user)
        & (summary["window_duration"] <= pd.Timedelta(hours=window_hours))
    ].copy()

    return sprays


def detect_multihost_targeting(auth_data):
    min_unique_hosts = 3
    window_minutes = 15

    work_data = auth_data.copy()

    failures = work_data[
        (work_data["auth_service"] == "sshd")
        & (work_data["outcome"].isin(["failed", "failed_invalid_user"]))
    ].sort_values(["src_ip", "timestamp"])

    if failures.empty:
        return pd.DataFrame()

    summary = (
        failures.groupby("src_ip")
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            unique_hosts=("host", "nunique"),
            host_list=("host", lambda x: list(x.unique())),
            targeted_users=("username", lambda x: list(x.unique())),
        )
        .reset_index()
    )

    summary["window_duration"] = summary["last_seen"] - summary["first_seen"]

    multi_host = summary[
        (summary["unique_hosts"] >= min_unique_hosts)
        & (summary["window_duration"] <= pd.Timedelta(minutes=window_minutes))
    ].copy()

    multi_host["detection_type"] = "Multi-Host Horizontal Movement (T1021.004)"
    return multi_host


def check_logins_after_failures(auth_data, auth_detections):
    """Correlates candidate IPs across all auth detections against successful logins occurring AFTER attack completion."""
    correlated_results = []

    for detection_type, df in auth_detections.items():
        if df.empty or "src_ip" not in df.columns or "last_seen" not in df.columns:
            continue

        successes = auth_data[
            (auth_data["auth_service"] == "sshd")
            & (auth_data["outcome"] == "success")
        ].merge(df[["src_ip", "last_seen"]], on="src_ip")

        valid_logins = successes[
            successes["timestamp"] > successes["last_seen"]
        ].copy()

        if not valid_logins.empty:
            valid_logins["detection_type"] = detection_type
            correlated_results.append(
                valid_logins[
                    [
                        "timestamp",
                        "host",
                        "src_ip",
                        "username",
                        "event_type",
                        "detection_type",
                    ]
                ]
            )

    if correlated_results:
        return pd.concat(correlated_results, ignore_index=True).drop_duplicates()

    return pd.DataFrame()