import numpy as np
import pandas as pd

AUTH_TEMPLATES = [
    # 1. OpenSSH Server Daemon (sshd)
    {
        "service": "sshd",
        "outcome": "success",
        "event_type": "password_auth",
        "pattern": r"Accepted password for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<port>\d+) ssh2",
    },
    {
        "service": "sshd",
        "outcome": "success",
        "event_type": "publickey_auth",
        "pattern": r"Accepted publickey for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<port>\d+) ssh2:\s+(?P<key_type>\S+)\s+(?P<fingerprint>\S+)",
    },
    {
        "service": "sshd",
        "outcome": "failed",
        "event_type": "password_auth",
        "pattern": r"Failed password for (?P<username>\S+) from (?P<src_ip>\S+) port (?P<port>\d+) ssh2",
    },
    {
        "service": "sshd",
        "outcome": "failed_invalid_user",
        "event_type": "password_auth",
        "pattern": r"Failed password for invalid user (?P<username>\S+) from (?P<src_ip>\S+) port (?P<port>\d+) ssh2",
    },
    {
        "service": "sshd",
        "outcome": "connection_dropped",
        "event_type": "preauth_disconnect",
        "pattern": r"Connection closed by authenticating user (?P<username>\S+) (?P<src_ip>\S+) port (?P<port>\d+) \[preauth\]",
    },
    {
        "service": "sshd",
        "outcome": "disconnect",
        "event_type": "user_disconnect",
        "pattern": r"Received disconnect from (?P<src_ip>\S+) port (?P<port>\d+):11:\s+user request",
    },
    {
        "service": "sshd",
        "outcome": "connection_closed",
        "event_type": "network_close",
        "pattern": r"Connection closed by (?P<src_ip>\S+) port (?P<port>\d+)",
    },
    # 2. System Login Manager (systemd-logind)
    {
        "service": "systemd-logind",
        "outcome": "session_created",
        "event_type": "session_lifecycle",
        "pattern": r"New session (?P<session_id>\S+) of user (?P<username>\S+)\.",
    },
    {
        "service": "systemd-logind",
        "outcome": "session_logout",
        "event_type": "session_lifecycle",
        "pattern": r"Session (?P<session_id>\S+) logged out\. Waiting for remaining processes\.\.\.",
    },
    {
        "service": "systemd-logind",
        "outcome": "session_removed",
        "event_type": "session_lifecycle",
        "pattern": r"Removed session (?P<session_id>\S+)\.",
    },
    {
        "service": "systemd-logind",
        "outcome": "hardware_event",
        "event_type": "system_monitoring",
        "pattern": r"(?P<action>Watching system buttons)",
    },
    # 3. Pluggable Authentication Modules (pam_unix)
    {
        "service": "pam_unix",
        "outcome": "failed",
        "event_type": "pam_auth",
        "pattern": r"(?:(?P<auth_service>\S+):)?pam_unix\(\S+:auth\):\s+authentication failure;.*?user=(?P<target_user>\S+)",
    },
    {
        "service": "pam_unix",
        "outcome": "session_opened",
        "event_type": "pam_session",
        "pattern": r"(?:(?P<auth_service>\S+):)?pam_unix\(\S+:session\):\s+session opened for user (?P<username>\S+) by \(uid=(?P<calling_uid>\d+)\)",
    },
    {
        "service": "pam_unix",
        "outcome": "session_closed",
        "event_type": "pam_session",
        "pattern": r"(?:(?P<auth_service>\S+):)?pam_unix\(\S+:session\):\s+session closed for user (?P<username>\S+)",
    },
    {
        "service": "pam_unix",
        "outcome": "password_changed",
        "event_type": "credential_change",
        "pattern": r"(?:passwd:)?pam_unix\(passwd:chauthtok\):\s+password changed for (?P<username>\S+)",
    },
    # 4. Administrative Privilege Escalation (sudo)
    {
        "service": "sudo",
        "outcome": "success",
        "event_type": "privilege_escalation",
        "pattern": r"(?:sudo:\s+)?(?P<username>\S+)\s+:\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)",
    },
    {
        "service": "sudo",
        "outcome": "failed",
        "event_type": "privilege_escalation",
        "pattern": r"(?:sudo:\s+)?(?P<username>\S+)\s+:\s+1 incorrect password attempt\s+;\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)",
    },
    {
        "service": "sudo",
        "outcome": "policy_violation",
        "event_type": "privilege_escalation",
        "pattern": r"(?:sudo:\s+)?(?P<username>\S+)\s+:\s+user NOT in sudoers\s+;\s+TTY=(?P<tty>\S+)\s+;\s+PWD=(?P<pwd>\S+)\s+;\s+USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.*)",
    },
    # 5. Direct User Switching (su)
    {
        "service": "su",
        "outcome": "success",
        "event_type": "identity_switch",
        "pattern": r"Successful su for (?P<target_user>\S+) by (?P<username>\S+)",
    },
    {
        "service": "su",
        "outcome": "failed",
        "event_type": "identity_switch",
        "pattern": r"FAILED SU \(to (?P<target_user>\S+)\) (?P<username>\S+) on (?P<tty>\S+)",
    },
    {
        "service": "su",
        "outcome": "session_assigned",
        "event_type": "identity_switch",
        "pattern": r"\+\s+(?P<tty>\S+)\s+(?P<username>\S+):(?P<target_user>\S+)",
    },
    # 6. PolicyKit Framework (polkitd & pkexec)
    {
        "service": "polkitd",
        "outcome": "success",
        "event_type": "policykit_authorization",
        "pattern": r"Operator of unix-session:(?P<session_id>\S+) successfully authenticated as user (?P<target_user>\S+) to gain (?P<auth_type>\S+) authorization for action (?P<action_id>\S+)",
    },
    {
        "service": "polkitd",
        "outcome": "unauthenticated_request",
        "event_type": "policykit_authorization",
        "pattern": r"(?P<event_details>Unauthenticated user requested check for authorization_id)",
    },
    {
        "service": "pkexec",
        "outcome": "session_opened",
        "event_type": "policykit_escalation",
        "pattern": r"(?:pkexec:\s+)?pam_unix\(polkit-1:session\):\s+session opened for user (?P<target_user>\S+) by \(uid=(?P<calling_uid>\d+)\)",
    },
    # 7. User and Group Database Alterations (useradd, groupadd, usermod, gpasswd)
    {
        "service": "useradd",
        "outcome": "account_created",
        "event_type": "user_management",
        "pattern": r"new user: name=(?P<username>\S+), uid=(?P<uid>\d+), gid=(?P<gid>\d+)",
    },
    {
        "service": "groupadd",
        "outcome": "group_created",
        "event_type": "group_management",
        "pattern": r"new group: name=(?P<group_name>\S+), gid=(?P<gid>\d+)",
    },
    {
        "service": "usermod",
        "outcome": "password_changed",
        "event_type": "user_management",
        "pattern": r"change user \'(?P<username>[^\']+)\' password",
    },
    {
        "service": "gpasswd",
        "outcome": "group_injection",
        "event_type": "group_management",
        "pattern": r"user (?P<username>\S+) added by (?P<admin>\S+) to group (?P<group_name>\S+)",
    },
    # 8. Automated Task Management (cron / anacron)
    {
        "service": "cron",
        "outcome": "session_opened",
        "event_type": "cron_execution",
        "pattern": r"(?:CRON\[\d+\]:\s+)?pam_unix\(cron:session\):\s+session opened for user (?P<username>\S+) by \(uid=(?P<calling_uid>\d+)\)",
    },
]


def parse_auth_data(auth_masked):

    df = auth_masked.copy()

    schema_cols = [
        "auth_service",
        "outcome",
        "event_type",
        "username",
        "target_user",
        "src_ip",
        "port",
        "session_id",
        "command",
        "tty",
        "calling_uid",
    ]
    for col in schema_cols:
        if col not in df.columns:
            df[col] = None

    for tmpl in AUTH_TEMPLATES:
        extracted = df["message"].str.extract(tmpl["pattern"])
        matched_mask = extracted.notna().any(axis=1) & df["outcome"].isna()

        if matched_mask.any():
            df.loc[matched_mask, "auth_service"] = tmpl["service"]
            df.loc[matched_mask, "outcome"] = tmpl["outcome"]
            df.loc[matched_mask, "event_type"] = tmpl["event_type"]

            for col in extracted.columns:
                if isinstance(col, str):
                    df.loc[matched_mask, col] = extracted.loc[
                        matched_mask, col
                    ]

    return df