# Ground Truth Answer Key

## Incident Summary
An external adversary (`198.51.100.45`) successfully brute-forced the `svc_web` account on `node1`. Reconnaissance on `node1` led to the discovery of `/etc/webapp/db_backend_link.conf`, which revealed `node2`'s role. The adversary pivoted to `node2` via SSH using the `data_sync` account, archived sensitive files from `/var/lib/financial_vault/`, and exfiltrated the archive to an external server (`203.0.113.99`).

## Incident Sequence
1. **Initial Access**: 198.51.100.45 brute-forced `node1` via SSH (Direct Evidence: `auth.log` failed/accepted passwords).
2. **Discovery**: Intruder ran `cat /etc/webapp/db_backend_link.conf` on `node1` (Direct Evidence: `syslog` audit EXECVE). This provided the motivation to target `node2`.
3. **Lateral Movement**: SSH session established from `node1` to `node2` as `data_sync` (Direct Evidence: `auth.log` on `node2`).
4. **Preparation**: Intruder executed `tar -czf /tmp/sync_cache.tar.gz /var/lib/financial_vault/` on `node2` (Direct Evidence: `syslog` audit).
5. **Exfiltration**: Intruder used `curl` to upload the archive to `https://203.0.113.99/upload`. Corroborated by `eve.json` showing an 8.5MB outbound flow to `203.0.113.99` over port 443.

## Benign Distractions
- **Vulnerability Scan**: `10.50.0.250` triggered a Suricata alert against `node3`. This is a distraction; the IP is an internal scanner (inferred from subnet) and no successful access or lateral movement followed.

## Uncertainties
- The logs do not prove the exact contents of the exfiltrated vault, only that the directory was archived and a data transfer of corresponding size occurred. 
