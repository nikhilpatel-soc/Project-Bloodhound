"""
Project Bloodhound File Analysis
Module: Log File Parser
Description: Reads and parses system and sensor logs into structured 
             dictionaries for security analysis.
"""

import os
import re
import tomllib
import json
import sys
import subprocess
import pandas as pd
from auth_parser import parse_auth_data
from auth_analysis_detections import (
    detect_ss_brute_force,
    detect_credential_spray,
    detect_multihost_targeting,
    check_logins_after_failures,
)
from net_analysis_detections import (
    detect_port_scan,
    detect_net_multihost_targeting,
    detect_large_outbound_transfer,
    detect_suricata_alerts,
)
from correlation_analysis import correlate_cross_source
from unified_timeline import generate_unified_timeline
from analysis_report import generate_analysis_report


def read_config_file(known_log_types, config_file):
    with open(config_file, "rb") as file:
        config = tomllib.load(file)
        
        root = config.get("root_directory", ".")
        nodes = config.get("nodes", ["node1", "node2", "node3", "node4"])
        node_logs = config.get("node_logs", ["auth.log", "syslog"])
        
        # Robust resolution for sensor list
        raw_sensors = config.get("sensors", config.get("sensor", None))
        if isinstance(raw_sensors, list) and raw_sensors:
            sensors = raw_sensors
        elif isinstance(raw_sensors, str) and raw_sensors:
            sensors = [raw_sensors]
        else:
            sensors = ["sensor"]

        # Robust resolution for sensor log types
        raw_sensor_logs = config.get("sensor_logs", None)
        if isinstance(raw_sensor_logs, list) and raw_sensor_logs:
            sensor_logs = raw_sensor_logs
        elif isinstance(raw_sensor_logs, str) and raw_sensor_logs:
            sensor_logs = [raw_sensor_logs]
        else:
            sensor_logs = ["eve.json"]

        node_ips = config.get("node_ips", {})

        for log_type in node_logs + sensor_logs:
            if log_type not in known_log_types:
                sys.exit(f"Unknown log type '{log_type}' encountered in {config_file}. Exiting.")

        log_files_meta = [
            [nodes, node_logs],
            [sensors, sensor_logs]
        ]
        
        log_files = []
        for log in node_logs:
            for node in nodes:
                log_files.append({
                    "host": node,
                    "log_type": log,
                    "file_path": os.path.join(root, node, log)
                })

        for log in sensor_logs:
            for sensor in sensors:
                log_files.append({
                    "host": sensor,
                    "log_type": log,
                    "file_path": os.path.join(root, sensor, log)
                })

        return log_files_meta, log_files, node_ips


def read_node_logs(log_files, data_state):

    parser = {
        "auth.log" : {
            "coarse" :  lambda line: line.split(maxsplit=3),
            "fine" : re.compile(r"(.+)\[(.*)\]"),
            "column_titles" : ["timestamp", "host", "process", "pid", "message"],
        },
        "syslog" : {
            "coarse" : lambda line: line.split(maxsplit=3),
            "fine" : re.compile(r"(.+)\[(.*)\]"),
            "column_titles" : ["timestamp", "host", "process", "pid", "message"]
        },
        "eve.json" : {
            "coarse": json.loads,
            "fine": None,
            "column_titles" : None,
        }
    }

    log_data_ingest = []
    for entry in log_files:
        print(f"Importing {entry["file_path"]} ...", end="")
        log_type = entry["log_type"]
        coarse_parse_type = parser[log_type]["coarse"]
        fine_parse_type = parser[log_type]["fine"]
        host = entry["host"]

        explicit_column_titles = parser[log_type]["column_titles"]
        if explicit_column_titles:
            data_type = ["log_type"] + parser[log_type]["column_titles"]
        else:
            data_type = None

        with open(entry["file_path"], "r") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                coarse_parsed = coarse_parse_type(line)
                if fine_parse_type:
                    if match := fine_parse_type.search(coarse_parsed[2]):
                        parsed = [log_type] + coarse_parsed[0:2] + list(match.groups()) + [coarse_parsed[3]]
                        log_data_ingest.append(dict(zip(data_type,parsed)))
                    else:
                        sys.exit(f"Error reading {entry}.  Quitting.")
                else:
                    log_data_ingest.append({"host": host} | {"log_type": log_type} | coarse_parsed)
            print("done")

    data_state["log_data"] = pd.DataFrame(log_data_ingest)
    data_state["log_data"]["timestamp"] = pd.to_datetime(
        data_state["log_data"]["timestamp"],
        errors="coerce",
        format="mixed"
    )

    input("Enter to continue...")

    return


def file_import(log_files_meta, log_files, data_state):
    nodes = log_files_meta[0][0]
    node_log_types = log_files_meta[0][1]
    sensors = log_files_meta[1][0]
    sensor_log_types = log_files_meta[1][1]

    while True:
        subprocess.run(["clear"])
        menu_options = {
            "1": lambda: read_node_logs(log_files, data_state),
        }

        print(f"""
====================================================================
                        LOG IMPORT MENU
====================================================================
  1. Import Log Files
  0. Return to Previous Menu

--------------------------------------------------------------------
                   CONFIGURATION FILE SUMMARY
--------------------------------------------------------------------

  Nodes            : {", ".join(nodes)}
  Node Log Types   : {", ".join(node_log_types)}
  Sensors          : {", ".join(sensors)}
  Sensor Log Types : {", ".join(sensor_log_types)}
====================================================================
        """)

        selection = input("Select an Option: ")

        if selection == "0":
            return
        else:
            read_node_logs(log_files, data_state)


def data_summary(data_state):
    subprocess.run(["clear"])

    if data_state["log_data"].empty:
        print("No log files imported.  Please import log files first.")
        input("Press enter to continue...")
        return

    data_state["log_data_meta"] = (
        data_state["log_data"]
        .groupby(["host", "log_type"])
        .agg(
            event_count=("timestamp", "count"),
            earliest_event=("timestamp", "min"),
            latest_event=("timestamp", "max")
        )
        .reset_index()
    )

    global_earliest_event = data_state["log_data_meta"]["earliest_event"].min()
    global_latest_event = data_state["log_data_meta"]["latest_event"].max()
    global_time_window = global_latest_event - global_earliest_event

    display_data_state = data_state["log_data_meta"].copy()
    display_data_state["host"] = display_data_state["host"].mask(display_data_state["host"].duplicated(), "")
    output_table = display_data_state.to_string(
        index=False,
        formatters={
            "earliest_event": lambda x: x.strftime("%Y-%m-%d %H:%M:%S"),
            "latest_event": lambda x: x.strftime("%Y-%m-%d %H:%M:%S")
        }
    )

    print(output_table, end="\n\n")

    print(f"""
    Global Start Time           Global End Time         Global Time Window
{global_earliest_event}  {global_latest_event}      {global_time_window}
    """)

    input("Press enter to continue...")
    return


def auth_analysis(data_state):
    if data_state["log_data"].empty:
        print("No log files imported. Please import log files first.")
        return


    auth_masked = data_state["log_data"][
        data_state["log_data"]["log_type"] == "auth.log"
    ].copy()

    if auth_masked.empty:
        print("No auth.log entries found in imported log data.")
        return


    auth_data = parse_auth_data(auth_masked)
    data_state["auth_data"] = auth_data

  
    auth_detections = {
        "ss_brute_force": detect_ss_brute_force(auth_data),
        "credential_spray": detect_credential_spray(auth_data),
        "multihost_targeting": detect_multihost_targeting(auth_data),
    }
    data_state["auth_detections"] = auth_detections


    compromise_success = check_logins_after_failures(auth_data, auth_detections)
    data_state["compromise_success"] = compromise_success

  
    print("\n" + "=" * 50)
    print("      AUTHENTICATION DETECTION SUMMARY")
    print("=" * 50)

    for rule_name, df in auth_detections.items():
        print(f"\n[{rule_name.upper()}] - {len(df)} candidate IP(s) detected")
        if not df.empty:
            print(df.to_string(index=False))

    print("\n" + "=" * 50)
    print("      SUCCESSFUL LOGINS FROM FLAGGED SOURCES")
    print("=" * 50)
    if not compromise_success.empty:
        print(compromise_success.to_string(index=False))
    else:
        print("No post-failure successful logins detected from flagged sources.")

    input("\nPress Enter to continue...")

    return auth_detections


def net_analysis(data_state):
    if data_state["log_data"].empty:
        print("No log files imported. Please import log files first.")
        return {}

  
    net_masked = data_state["log_data"][
        data_state["log_data"]["log_type"] == "eve.json"
    ].copy()

    if net_masked.empty:
        print("No eve.json entries found in imported log data.")
        net_detections = {
            "port_scan": pd.DataFrame(),
            "multihost_targeting": pd.DataFrame(),
            "large_transfer": pd.DataFrame(),
            "suricata_alerts": pd.DataFrame(),
        }
        data_state["network_data"] = pd.DataFrame()
        data_state["network_detections"] = net_detections
        return net_detections

    data_state["network_data"] = net_masked


    net_detections = {
        "port_scan": detect_port_scan(net_masked),
        "multihost_targeting": detect_net_multihost_targeting(net_masked),
        "large_transfer": detect_large_outbound_transfer(net_masked),
        "suricata_alerts": detect_suricata_alerts(net_masked),
    }
    data_state["network_detections"] = net_detections


    print("\n" + "=" * 68)
    print("                     NETWORK ACTIVITY ANALYSIS")
    print("=" * 68)

    print("\nPORT-SCAN DETECTIONS")
    print("-" * 68)
    df_ps = net_detections["port_scan"]
    if not df_ps.empty:
        print(df_ps.to_string(index=False))
    else:
        print("No detections")

    print("\nMULTI-HOST TARGETING DETECTIONS")
    print("-" * 68)
    df_mh = net_detections["multihost_targeting"]
    if not df_mh.empty:
        print(df_mh.to_string(index=False))
    else:
        print("No detections")

    print("\nLARGE OUTBOUND TRANSFER DETECTIONS")
    print("-" * 68)
    df_lt = net_detections["large_transfer"]
    if not df_lt.empty:
        print(df_lt.to_string(index=False))
    else:
        print("No detections")

    print("\nSURICATA ALERTS")
    print("-" * 68)
    df_sa = net_detections["suricata_alerts"]
    if not df_sa.empty:
        print(df_sa.to_string(index=False))
    else:
        print("No alerts")

    input("\npress enter to continue....")

    return net_detections


def correlation_analysis(data_state):

    if "auth_detections" not in data_state or not data_state["auth_detections"]:
        print("Error: Authentication Analysis (Option 3) must be run before Cross-Source Correlation.")
        input("\nPress Enter to continue...")
        return

    if "network_detections" not in data_state or not data_state["network_detections"]:
        print("Error: Network Activity Analysis (Option 4) must be run before Cross-Source Correlation.")
        input("\nPress Enter to continue...")
        return


    chains = correlate_cross_source(data_state)
    data_state["correlated_chains"] = chains

    print("\n" + "=" * 68)
    print("                     CROSS-SOURCE CORRELATION")
    print("=" * 68)
    print("CORRELATED ACTIVITY CHAINS\n")

    if not chains:
        print("No cross-source activity chains correlated across current evidence.")
    else:
        for chain in chains:
            print(f"[{chain['chain_id']}]")
            print(f"Host: {chain['host']} ({chain['host_ip']})")

            init = chain["initial_auth"]
            ts_str = init["login_time"].strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"Authentication: Successful {init['event_type']} from {init['src_ip']} as '{init['username']}' at {ts_str}"
            )

            if chain["syslog_context"]:
                print("System context:")
                for event in chain["syslog_context"]:
                    print(f"  └─ {event}")
            else:
                print("System context: None observed")

            if chain["network_activity"]:
                print("Network activity:")
                for net_act in chain["network_activity"]:
                    print(f"  └─ {net_act}")

            if chain["lateral_movement"]:
                print("Lateral movement:")
                for lat in chain["lateral_movement"]:
                    print(f"  └─ {lat}")

            print(f"Evidence sources: {', '.join(chain['evidence_sources'])}")

            start_str = chain["time_range"]["start"].strftime("%Y-%m-%d %H:%M:%S")
            end_str = chain["time_range"]["end"].strftime("%Y-%m-%d %H:%M:%S")
            print(f"Time range: {start_str} to {end_str}")
            print(f"Findings: {', '.join(chain['findings'])}\n" + "-" * 68)

    input("\nPress Enter to continue...")
    return chains

def unified_timeline_analysis(data_state):

    if data_state.get("correlated_chains") is None:
        print("Error: Cross-Source Correlation (Option 5) must be run before Unified Timeline.")
        input("\nPress Enter to continue...")
        return pd.DataFrame()

    timeline_df = generate_unified_timeline(data_state)
    data_state["unified_timeline"] = timeline_df


    print("\n" + "=" * 95)
    print("                                   UNIFIED TIMELINE")
    print("=" * 95 + "\n")

    if timeline_df.empty:
        print("No timeline events generated from current evidence.")
    else:
        print(f"{'TIMESTAMP (UTC)':<20} {'HOST':<7} {'EVENT TYPE':<22} {'EVIDENCE':<10} {'CORR ID':<8} {'DESCRIPTION'}")
        print("-" * 95)
        for _, row in timeline_df.iterrows():
            ts_str = row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(row["timestamp"]) else "N/A"
            host_str = str(row["host"])
            type_str = str(row["event_type"])
            src_str = str(row["evidence_source"])
            corr_str = str(row["correlation_id"])
            desc_str = str(row["description"])
            print(f"{ts_str:<20} {host_str:<7} {type_str:<22} {src_str:<10} {corr_str:<8} {desc_str}")

    input("\nPress Enter to continue...")
    return timeline_df

def analysis_report_view(data_state):

    prereqs = ["auth_detections", "network_detections", "correlated_chains", "unified_timeline"]
    for req in prereqs:
        if req not in data_state or data_state[req] is None or (isinstance(data_state[req], (dict, list, pd.DataFrame)) and len(data_state[req]) == 0 and req == "unified_timeline" and data_state.get("correlated_chains") is None):
            print(f"Error: All analysis steps (Options 3–6) must be completed before generating the Analysis Report.")
            input("\nPress Enter to continue...")
            return

    report_text = generate_analysis_report(data_state)

    subprocess.run(["clear"])
    print(report_text)

    input("\nPress Enter to continue...")
    return report_text

# Main Body
config_file = "config.toml"
known_log_types = ["auth.log", "syslog", "eve.json"]
log_files_meta, log_files, node_ips = read_config_file(known_log_types, config_file)
data_state = {
    "log_data_meta": pd.DataFrame(),
    "log_data": pd.DataFrame(),
    "auth_data": pd.DataFrame(),
    "auth_detections": {},
    "network_data": pd.DataFrame(),
    "network_detections": {},
    "correlated_chains": None,
    "compromise_success": pd.DataFrame(),
    "node_ip_map": node_ips,
    "unified_timeline": pd.DataFrame(),
    "analysis_report": "",
}

menu_options = {
    "1": lambda: file_import(log_files_meta, log_files, data_state),
    "2": lambda: data_summary(data_state),
    "3": lambda: (
        data_state.update({"auth_detections": auth_analysis(data_state)}),
        data_state.update({"network_detections": net_analysis(data_state)}),
        data_state.update({"correlated_chains": correlation_analysis(data_state)}),
        data_state.update({"unified_timeline": unified_timeline_analysis(data_state)})
    ),
    "4": lambda: data_state.update({"analysis_report": analysis_report_view(data_state)}),
    "0": sys.exit,
}

while True:
    subprocess.run(["clear"])
    print(f"""
==================================================
                PROJECT BLOODHOUND
==================================================

1. Import Log Files             (in alpha)
2. Evidence Overview            (in alpha)
3. Analyze Log Data             (in_alpha)
4. Analysis Report              (in_alpha)

0. Exit
    """)

    selection = input("Select an option: ")

    for key, value in menu_options.items():
        if key == selection:
            value()

#    file_import(log_files_meta, log_files, data_state)
#    data_state["auth_detections"] = auth_analysis(data_state)
#    data_state["network_detections"] = net_analysis(data_state)
#    data_state["correlated_chains"] = correlation_analysis(data_state)
#    data_state["unified_timeline"] = unified_timeline_analysis(data_state)
#    data_state["analysis_report"] = analysis_report_view(data_state)
