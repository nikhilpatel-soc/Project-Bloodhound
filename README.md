# Project Bloodhound: Multi-Source Log Analysis & Incident Reconstruction

Project Bloodhound is a deterministic, rule-based Python application designed to ingest, parse, normalize, and correlate heterogeneous Linux host logs (`auth.log`, `syslog`) and Suricata network traffic records (`eve.json`) across monitored network nodes.

## Key Capabilities

- **Multi-Source Ingestion & Normalization:** Parses unstructured Linux syslog/auth.log text entries and Suricata NDJSON records into unified data structures.
- **Rule-Based Detection Engines:**
  - *Authentication:* Flags single-source brute force, credential spraying, and multi-host targeting attempts.
  - *Network:* Detects port scanning, multi-host targeted probing, and large outbound data transfers.
- **Cross-Source Correlation:** Correlates successful SSH logins from flagged sources with subsequent host commands (`syslog`) and network alerts (`eve.json`) over dynamic forward time windows using explicit node-to-IP mapping.
- **Unified Timeline & Reporting:** Deduplicates and chronologically orders correlated findings into a structured incident report.

## Application Architecture

```text
├── bloodhound.py                # Core CLI, state manager, and pipeline orchestration
├── config.toml                  # Node-to-IP mappings, log paths, and environmental settings
└── modules/
    ├── auth_parser.py           # Regex template parsing for Linux authentication logs
    ├── auth_analysis_detections # Authentication anomaly detection rules
    ├── net_analysis_detections  # Suricata network anomaly detection rules
    ├── correlation_analysis.py  # Cross-log correlation engine
    ├── unified_timeline.py      # Chronological timeline builder
    └── analysis_report.py       # Automated formatted text report generator
