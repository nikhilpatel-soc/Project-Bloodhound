import pandas as pd


def generate_unified_timeline(data_state):
    """
    Normalizes evidence from options 3, 4, and 5 into a unified timeline with
    robust Suricata endpoint mapping, unique event representation, and correlation IDs.
    """
    timeline_records = []

    raw_map = data_state.get("node_ip_map", {})
    host_to_ip = {}
    ip_to_host = {}

    for host_name, ip_val in raw_map.items():
        if isinstance(ip_val, list):
            if ip_val:
                host_to_ip[host_name] = str(ip_val[0])
                for ip in ip_val:
                    ip_to_host[str(ip)] = host_name
        elif isinstance(ip_val, str):
            host_to_ip[host_name] = ip_val
            ip_to_host[ip_val] = host_name

    def resolve_host_and_ip(raw_val):
        s = str(raw_val)
        if s in host_to_ip:
            return s, host_to_ip[s]
        if s in ip_to_host:
            return ip_to_host[s], s
        for h, ip in host_to_ip.items():
            if s == ip or s in ip:
                return h, ip
        return s, s

    # 1. Option 3: Auth Detections
    auth_detections = data_state.get("auth_detections", {})
    for rule_name, df in auth_detections.items():
        if df.empty:
            continue
        for _, row in df.iterrows():
            host_name, host_ip = resolve_host_and_ip(row.get("host", "global"))
            ts = pd.to_datetime(row.get("last_seen", row.get("timestamp", pd.NaT)))
            if pd.isna(ts):
                continue
            
            if rule_name == "ss_brute_force":
                count = row.get("failed_count", "Multiple")
                src_ip = row.get("src_ip", "unknown")
                user = row.get("username", "unknown")
                desc = f"Repeated SSH failures ({count} attempts from {src_ip} for '{user}') on {host_name} ({host_ip})"
            elif rule_name == "credential_spray":
                total = row.get("total_failed", "Multiple")
                users = len(row.get("targeted_users", []))
                src_ip = row.get("src_ip", "unknown")
                desc = f"Credential spray: {total} failures targeting {users} users from {src_ip}"
            elif rule_name == "multihost_targeting":
                hosts_hit = row.get("unique_hosts", 2)
                src_ip = row.get("src_ip", "unknown")
                desc = f"Multi-host targeting across {hosts_hit} hosts from {src_ip}"
            else:
                desc = f"Auth detection rule triggered: {rule_name}"

            timeline_records.append({
                "timestamp": ts,
                "host": host_name,
                "event_type": "AUTH DETECTION",
                "description": desc,
                "evidence_source": "auth.log",
                "correlation_id": "N/A"
            })

    # 2. Option 5 Correlated Chains (Captures logins, syslog, network alerts, lateral movement)
    correlated_chains = data_state.get("correlated_chains", [])
    chain_login_timestamps = set()

    for chain in correlated_chains:
        chain_id = chain.get("chain_id", "COR")
        host_name, host_ip = resolve_host_and_ip(chain.get("host", "unknown"))
        init = chain.get("initial_auth", {})
        login_ts = pd.to_datetime(init.get("login_time"))

        if pd.notna(login_ts):
            chain_login_timestamps.add(login_ts)
            desc = f"Login from flagged source {init.get('src_ip')} as '{init.get('username')}' on {host_name} ({host_ip})"
            timeline_records.append({
                "timestamp": login_ts,
                "host": host_name,
                "event_type": "SUCCESSFUL LOGIN",
                "description": desc,
                "evidence_source": "auth.log",
                "correlation_id": chain_id
            })

        for syslog_ev in chain.get("syslog_context", []):
            timeline_records.append({
                "timestamp": syslog_ev["timestamp"],
                "host": host_name,
                "event_type": "SYSTEM CONTEXT",
                "description": f"{syslog_ev['description']} on {host_name} ({host_ip})",
                "evidence_source": "syslog",
                "correlation_id": chain_id
            })

        for net_ev in chain.get("network_activity", []):
            timeline_records.append({
                "timestamp": net_ev["timestamp"],
                "host": host_name,
                "event_type": net_ev["event_type"],
                "description": net_ev["description"],
                "evidence_source": net_ev["evidence_source"],
                "correlation_id": chain_id
            })

        for lat_ev in chain.get("lateral_movement", []):
            timeline_records.append({
                "timestamp": lat_ev["timestamp"],
                "host": host_name,
                "event_type": lat_ev["event_type"],
                "description": lat_ev["description"],
                "evidence_source": lat_ev["evidence_source"],
                "correlation_id": chain_id
            })

    # 3. Option 3 / Standalone Successful Logins not in Option 5 chains
    compromises = data_state.get("compromise_success", pd.DataFrame())
    if not compromises.empty:
        for _, row in compromises.iterrows():
            ts = pd.to_datetime(row.get("timestamp"))
            if pd.isna(ts) or ts in chain_login_timestamps:
                continue
            host_name, host_ip = resolve_host_and_ip(row.get("host", "unknown"))
            desc = f"Login from flagged source {row.get('src_ip')} as '{row.get('username')}' on {host_name} ({host_ip})"
            timeline_records.append({
                "timestamp": ts,
                "host": host_name,
                "event_type": "SUCCESSFUL LOGIN",
                "description": desc,
                "evidence_source": "auth.log",
                "correlation_id": "N/A"
            })

    # 4. Standalone Network Detections (Option 4) with Correct Endpoint Attribution
    network_detections = data_state.get("network_detections", {})
    for det_type, df in network_detections.items():
        if df.empty:
            continue
        for _, row in df.iterrows():
            ts = pd.to_datetime(row.get("last_seen", row.get("timestamp", row.get("first_seen", pd.NaT))))
            if pd.isna(ts):
                continue

            if det_type == "port_scan":
                host_name, host_ip = resolve_host_and_ip(row.get("dest_ip", "sensor"))
                desc = f"Port scan from {row.get('src_ip', 'unknown')} targeting {host_name} ({host_ip}) ({row.get('unique_ports', 0)} ports)"
                ev_type = "PORT SCAN"
            elif det_type == "multihost_targeting":
                host_name, host_ip = resolve_host_and_ip(row.get("src_ip", "sensor"))
                desc = f"Multi-host network targeting from {host_name} ({host_ip})"
                ev_type = "MULTI-HOST TARGETING"
            elif det_type == "large_transfer":
                src_ip = row.get("src_ip", "unknown")
                host_name, host_ip = resolve_host_and_ip(src_ip)
                bytes_val = row.get("total_bytes_sent", 0)
                desc = f"{bytes_val:,} bytes sent externally from {host_name} ({host_ip}) to {row.get('dest_ip', 'unknown')}"
                ev_type = "LARGE TRANSFER"
            elif det_type == "suricata_alerts":
                dest_ip = row.get("dest_ip")
                src_ip = row.get("src_ip")
                
                # Check dest_ip first; if not an internal node, check src_ip; else fallback to sensor
                target_ip = None
                if dest_ip and str(dest_ip) in ip_to_host:
                    target_ip = dest_ip
                elif src_ip and str(src_ip) in ip_to_host:
                    target_ip = src_ip
                else:
                    target_ip = dest_ip or src_ip or "sensor"

                host_name, host_ip = resolve_host_and_ip(target_ip)
                desc = f"Sensor-generated alert: {row.get('signature', 'Alert')} on {host_name} ({host_ip})"
                ev_type = "SURICATA ALERT"
            else:
                continue

            timeline_records.append({
                "timestamp": ts,
                "host": host_name,
                "event_type": ev_type,
                "description": desc,
                "evidence_source": "eve.json",
                "correlation_id": "N/A"
            })

    if not timeline_records:
        return pd.DataFrame()

    timeline_df = pd.DataFrame(timeline_records)
    
    # Unified deduplication covering normalized fields and timestamp proximity
    timeline_df = timeline_df.drop_duplicates(subset=["timestamp", "host", "event_type", "description"])
    timeline_df = timeline_df.sort_values(by="timestamp").reset_index(drop=True)

    return timeline_df