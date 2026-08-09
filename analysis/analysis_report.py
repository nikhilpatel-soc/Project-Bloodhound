import pandas as pd


def generate_analysis_report(data_state):
    """
    Consolidates completed analysis into a structured, human-readable report
    incorporating evidence analysis, authentication and network detections,
    correlated activity chains, the integrated unified timeline, and limitations.
    Stores the result in data_state["analysis_report"].
    """
    report_lines = []

    report_lines.append("====================================================================")
    report_lines.append("                            ANALYSIS REPORT")
    report_lines.append("====================================================================")
    report_lines.append("")

    # 1. EVIDENCE ANALYZED
    report_lines.append("EVIDENCE ANALYZED")
    report_lines.append("-" * 68)
    log_meta = data_state.get("log_data_meta", pd.DataFrame())
    if not log_meta.empty:
        for _, row in log_meta.iterrows():
            host = row.get("host", "unknown")
            l_type = row.get("log_type", "unknown")
            count = row.get("event_count", 0)
            earliest = row.get("earliest_event", "N/A")
            latest = row.get("latest_event", "N/A")
            report_lines.append(f"  Host: {host:<8} | Log Type: {l_type:<10} | Records: {count:<5} | Window: {earliest} to {latest}")
    else:
        report_lines.append("  No log metadata available.")
    report_lines.append("")

    # 2. AUTHENTICATION DETECTIONS
    report_lines.append("AUTHENTICATION DETECTIONS")
    report_lines.append("-" * 68)
    auth_dets = data_state.get("auth_detections", {})
    has_auth_dets = False
    for rule_name, df in auth_dets.items():
        if not df.empty:
            has_auth_dets = True
            if rule_name == "ss_brute_force":
                heading_label = "SINGLE-SOURCE BRUTE FORCE (T1110.001)"
            elif rule_name == "credential_spray":
                heading_label = "CREDENTIAL SPRAY (T1110.003)"
            elif rule_name == "multihost_targeting":
                heading_label = "MULTI-HOST HORIZONTAL MOVEMENT (T1021.004)"
            else:
                heading_label = rule_name.upper()

            report_lines.append(f"  [{heading_label}] - {len(df)} record(s) found:")
            for _, row in df.iterrows():
                host = row.get("host", "N/A")
                src_ip = row.get("src_ip", "N/A")
                user = row.get("username", "N/A")
                if rule_name == "ss_brute_force":
                    failed_count = row.get("failed_count", "N/A")
                    first = row.get("first_seen", "N/A")
                    last = row.get("last_seen", "N/A")
                    report_lines.append(f"    - Host: {host}, Src IP: {src_ip}, User: {user} | Failed Attempts: {failed_count} | Range: {first} to {last}")
                elif rule_name == "credential_spray":
                    total = row.get("total_failed", "N/A")
                    unique_u = row.get("unique_users", "N/A")
                    users_list = row.get("targeted_users", [])
                    first = row.get("first_seen", "N/A")
                    last = row.get("last_seen", "N/A")
                    report_lines.append(f"    - Src IP: {src_ip} | Total Failed: {total}, Unique Users: {unique_u} | Users: {users_list} | Range: {first} to {last}")
                elif rule_name == "multihost_targeting":
                    unique_h = row.get("unique_hosts", "N/A")
                    h_list = row.get("host_list", [])
                    users_list = row.get("targeted_users", [])
                    first = row.get("first_seen", "N/A")
                    last = row.get("last_seen", "N/A")
                    report_lines.append(f"    - Src IP: {src_ip} | Unique Hosts Hit: {unique_h} ({h_list}) | Targeted Users: {users_list} | Range: {first} to {last}")
                else:
                    report_lines.append(f"    - Host: {host}, Src IP: {src_ip}, User: {user}")
    if not has_auth_dets:
        report_lines.append("  No authentication detections recorded.")
    report_lines.append("")

    # 3. NETWORK DETECTIONS
    report_lines.append("NETWORK DETECTIONS")
    report_lines.append("-" * 68)
    net_dets = data_state.get("network_detections", {})
    has_net_dets = False
    for det_type, df in net_dets.items():
        if not df.empty:
            has_net_dets = True
            report_lines.append(f"  [{det_type.upper()}] - {len(df)} record(s) found:")
            for _, row in df.iterrows():
                src_ip = row.get("src_ip", "N/A")
                dest_ip = row.get("dest_ip", "N/A")
                first = row.get("first_seen", "N/A")
                last = row.get("last_seen", "N/A")
                if det_type == "port_scan":
                    ports = row.get("unique_ports", "N/A")
                    report_lines.append(f"    - Src IP: {src_ip}, Dest IP: {dest_ip} | Unique Ports: {ports} | Range: {first} to {last}")
                elif det_type == "large_transfer":
                    bytes_sent = row.get("total_bytes_sent", 0)
                    report_lines.append(f"    - Src IP: {src_ip}, Dest IP: {dest_ip} | Bytes Sent: {bytes_sent:,} | Range: {first} to {last}")
                elif det_type == "suricata_alerts":
                    sig = row.get("signature", "N/A")
                    ts = row.get("timestamp", "N/A")
                    report_lines.append(f"    - Timestamp: {ts} | Src IP: {src_ip}, Dest IP: {dest_ip} | Signature: {sig}")
                elif det_type == "multihost_targeting":
                    dest_port = row.get("dest_port", "N/A")
                    unique_h = row.get("unique_hosts", "N/A")
                    targeted_hosts = row.get("targeted_hosts", [])
                    targeted_hosts_str = ", ".join(str(h) for h in targeted_hosts) if isinstance(targeted_hosts, list) else str(targeted_hosts)
                    report_lines.append(f"    - Src IP: {src_ip} | Destination Port: {dest_port}")
                    report_lines.append(f"      Unique Hosts Targeted: {unique_h}")
                    report_lines.append(f"      Targeted Hosts: {targeted_hosts_str}")
                    report_lines.append(f"      Range: {first} to {last}")
                else:
                    report_lines.append(f"    - Src IP: {src_ip}, Dest IP: {dest_ip} | Range: {first} to {last}")
    if not has_net_dets:
        report_lines.append("  No network detections recorded.")
    report_lines.append("")

    # 4. CORRELATED ACTIVITY CHAINS
    report_lines.append("CORRELATED ACTIVITY CHAINS")
    report_lines.append("-" * 68)
    chains = data_state.get("correlated_chains", [])
    if not chains:
        report_lines.append("  No cross-source activity chains recorded.")
    else:
        for chain in chains:
            c_id = chain.get("chain_id", "COR")
            findings_str = " — ".join(chain.get("findings", ["CORRELATED ACTIVITY"]))
            report_lines.append(f"{c_id} — {findings_str}")
            report_lines.append("")
            
            tr = chain.get("time_range", {})
            start_str = str(tr.get("start", "N/A"))
            end_str = str(tr.get("end", "N/A"))
            report_lines.append(f"  Time range:            {start_str} to {end_str} UTC")
            
            init = chain.get("initial_auth", {})
            report_lines.append(f"  Authentication event: Successful {init.get('event_type', 'auth')} from flagged source {init.get('src_ip')} as '{init.get('username')}'")
            report_lines.append(f"  Target host:           {chain.get('host')} ({chain.get('host_ip')})")
            
            for net_act in chain.get("network_activity", []):
                if isinstance(net_act, dict):
                    ev_type = net_act.get("event_type", "NETWORK EVENT")
                    desc = net_act.get("description", "")
                    report_lines.append(f"  {ev_type:<22}: {desc}")
                else:
                    report_lines.append(f"  Network event:         {net_act}")
            
            for lat in chain.get("lateral_movement", []):
                if isinstance(lat, dict):
                    desc = lat.get("description", "")
                    report_lines.append(f"  Lateral movement:      {desc}")
                else:
                    report_lines.append(f"  Lateral movement:      {lat}")

            for sys_ev in chain.get("syslog_context", []):
                if isinstance(sys_ev, dict):
                    report_lines.append(f"  System context:        {sys_ev.get('description')}")

            report_lines.append(f"  Evidence sources:      {', '.join(chain.get('evidence_sources', []))}")
            report_lines.append(f"  Classifications:       {', '.join(chain.get('findings', []))}")
            report_lines.append("")

    # 5. UNIFIED TIMELINE (Embedded Directly)
    report_lines.append("UNIFIED TIMELINE")
    report_lines.append("-" * 68)
    timeline_df = data_state.get("unified_timeline", pd.DataFrame())
    if timeline_df.empty:
        report_lines.append("  No unified timeline available.")
    else:
        report_lines.append(f"  {'TIMESTAMP (UTC)':<20} {'HOST':<7} {'EVENT TYPE':<20} {'EVIDENCE':<10} {'CORR ID':<8} {'DESCRIPTION'}")
        report_lines.append("  " + "-" * 88)
        for _, row in timeline_df.iterrows():
            ts_str = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(row["timestamp"]) else "N/A"
            host_str = str(row["host"])
            type_str = str(row["event_type"])
            src_str = str(row.get("evidence_source", "N/A"))
            corr_str = str(row.get("correlation_id", "N/A"))
            desc_str = str(row.get("description", ""))
            report_lines.append(f"  {ts_str:<20} {host_str:<7} {type_str:<20} {src_str:<10} {corr_str:<8} {desc_str}")
    report_lines.append("")

    # 6. ANALYSIS LIMITATIONS
    report_lines.append("ANALYSIS LIMITATIONS")
    report_lines.append("-" * 68)
    report_lines.append("  - Analysis is strictly bounded by the provided log collection window and file integrity.")
    report_lines.append("  - Detection rules operate on heuristic pattern matching and signature thresholds.")
    report_lines.append("  - Cross-source correlations reflect temporal proximity and shared network endpoints,")
    report_lines.append("    not definitive proof of attacker intent or confirmed system compromise.")
    report_lines.append("")
    report_lines.append("====================================================================")
    report_lines.append("                             END OF REPORT")
    report_lines.append("====================================================================")

    report_text = "\n".join(report_lines)
    data_state["analysis_report"] = report_text
    return report_text