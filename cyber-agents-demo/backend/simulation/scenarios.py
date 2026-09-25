SCENARIOS = {
    "network_intrusion": {
        "name": "network_intrusion",
        "description": (
            "A sophisticated threat actor attempts to breach a corporate network, "
            "moving from initial reconnaissance through exploitation toward the crown jewel: "
            "the domain controller. The Blue Team must detect and isolate threats before "
            "critical assets are compromised."
        ),
        "difficulty": "medium",
        "network_topology": {
            "segments": [
                {
                    "name": "dmz",
                    "hosts": [
                        {"id": "web-server-01", "role": "web", "os": "linux", "services": ["http", "https"], "value": 2},
                        {"id": "mail-server-01", "role": "mail", "os": "linux", "services": ["smtp", "imap"], "value": 2},
                        {"id": "vpn-gateway", "role": "vpn", "os": "linux", "services": ["openvpn", "ssh"], "value": 3},
                    ],
                },
                {
                    "name": "internal",
                    "hosts": [
                        {"id": "workstation-01", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 3},
                        {"id": "workstation-02", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 3},
                        {"id": "file-server", "role": "fileserver", "os": "windows", "services": ["smb", "nfs"], "value": 5},
                        {"id": "dev-server", "role": "dev", "os": "linux", "services": ["ssh", "git", "jenkins"], "value": 4},
                    ],
                },
                {
                    "name": "critical",
                    "hosts": [
                        {"id": "domain-controller", "role": "dc", "os": "windows", "services": ["ldap", "kerberos", "dns"], "value": 10},
                        {"id": "backup-server", "role": "backup", "os": "linux", "services": ["rsync", "ssh"], "value": 7},
                        {"id": "siem-server", "role": "siem", "os": "linux", "services": ["elasticsearch", "kibana"], "value": 6},
                    ],
                },
            ],
            "firewall_rules": [
                {"from": "internet", "to": "dmz", "ports": [80, 443, 25, 993, 1194], "action": "allow"},
                {"from": "dmz", "to": "internal", "ports": [22, 445, 3389], "action": "allow"},
                {"from": "internal", "to": "critical", "ports": [389, 88, 53, 445], "action": "allow"},
                {"from": "dmz", "to": "critical", "ports": [], "action": "deny"},
            ],
            "entry_points": ["web-server-01", "vpn-gateway", "mail-server-01"],
        },
        "initial_red_objectives": [
            {
                "id": "obj_recon",
                "phase": "recon",
                "description": "Gather information about the target network using OSINT and passive scanning",
                "target_segment": "dmz",
                "completed": False,
            },
            {
                "id": "obj_scan",
                "phase": "scan",
                "description": "Perform active scanning to identify open ports and vulnerable services",
                "target_segment": "dmz",
                "completed": False,
            },
            {
                "id": "obj_exploit",
                "phase": "exploit",
                "description": "Exploit a vulnerability in the DMZ to gain initial foothold",
                "target_hosts": ["web-server-01", "vpn-gateway", "mail-server-01"],
                "completed": False,
            },
            {
                "id": "obj_pivot",
                "phase": "pivot",
                "description": "Pivot from DMZ to internal network, compromise workstations",
                "target_segment": "internal",
                "completed": False,
            },
            {
                "id": "obj_exfil",
                "phase": "exfil",
                "description": "Reach and compromise the domain controller to achieve full domain control",
                "target_hosts": ["domain-controller"],
                "completed": False,
            },
        ],
        "initial_blue_rules": [
            {
                "id": "rule_ids_01",
                "type": "ids",
                "description": "Alert on port scans exceeding 100 ports/minute from external sources",
                "trigger": "port_scan_threshold",
                "threshold": 100,
                "action": "alert",
                "enabled": True,
            },
            {
                "id": "rule_fw_01",
                "type": "firewall",
                "description": "Block inbound connections from known malicious IPs",
                "trigger": "known_bad_ip",
                "action": "block",
                "enabled": True,
            },
            {
                "id": "rule_siem_01",
                "type": "siem",
                "description": "Correlate failed login attempts across multiple hosts",
                "trigger": "brute_force_pattern",
                "threshold": 5,
                "action": "alert_and_lock",
                "enabled": True,
            },
            {
                "id": "rule_edr_01",
                "type": "edr",
                "description": "Detect lateral movement via unusual SMB access patterns",
                "trigger": "lateral_movement_smb",
                "action": "alert",
                "enabled": True,
            },
            {
                "id": "rule_isolate_01",
                "type": "isolation",
                "description": "Automatically isolate hosts with confirmed malware or active exploitation",
                "trigger": "confirmed_compromise",
                "action": "isolate",
                "enabled": True,
            },
        ],
        "victory_conditions": {
            "red": {
                "primary": "Compromise the domain controller (host id: domain-controller)",
                "secondary": "Exfiltrate data from the backup server without detection",
                "description": "Red Team wins by achieving full domain compromise via the domain controller.",
            },
            "blue": {
                "primary": "Detect and isolate all red team agents for 3 consecutive turns",
                "secondary": "Prevent compromise of domain controller and backup server",
                "description": "Blue Team wins by completely neutralizing the red team's presence on the network.",
            },
        },
    },
    "ransomware_outbreak": {
        "name": "ransomware_outbreak",
        "description": (
            "A ransomware operator gains initial access via a phishing email and attempts "
            "to spread laterally, encrypt critical data, and deploy ransomware on the domain controller. "
            "Blue Team must contain the outbreak before critical business systems are encrypted."
        ),
        "difficulty": "hard",
        "network_topology": {
            "segments": [
                {
                    "name": "user_network",
                    "hosts": [
                        {"id": "user-ws-01", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 2},
                        {"id": "user-ws-02", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 2},
                        {"id": "user-ws-03", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 2},
                        {"id": "user-ws-04", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 2},
                    ],
                },
                {
                    "name": "server_network",
                    "hosts": [
                        {"id": "file-server-main", "role": "fileserver", "os": "windows", "services": ["smb"], "value": 8},
                        {"id": "sql-server", "role": "database", "os": "windows", "services": ["mssql"], "value": 9},
                        {"id": "backup-server", "role": "backup", "os": "windows", "services": ["veeam", "smb"], "value": 7},
                        {"id": "domain-controller", "role": "dc", "os": "windows", "services": ["ldap", "kerberos", "dns"], "value": 10},
                    ],
                },
            ],
            "firewall_rules": [
                {"from": "internet", "to": "user_network", "ports": [443], "action": "allow"},
                {"from": "user_network", "to": "server_network", "ports": [445, 1433, 389], "action": "allow"},
            ],
            "entry_points": ["user-ws-01", "user-ws-02"],
        },
        "initial_red_objectives": [
            {
                "id": "obj_phish",
                "phase": "recon",
                "description": "Identify target users and craft convincing phishing emails",
                "target_segment": "user_network",
                "completed": False,
            },
            {
                "id": "obj_initial_access",
                "phase": "exploit",
                "description": "Gain initial access via phishing payload execution on a workstation",
                "target_hosts": ["user-ws-01", "user-ws-02"],
                "completed": False,
            },
            {
                "id": "obj_spread",
                "phase": "pivot",
                "description": "Spread ransomware to all workstations and file servers via SMB",
                "target_segment": "server_network",
                "completed": False,
            },
            {
                "id": "obj_encrypt_dc",
                "phase": "exfil",
                "description": "Deploy ransomware on domain controller to encrypt AD database",
                "target_hosts": ["domain-controller"],
                "completed": False,
            },
        ],
        "initial_blue_rules": [
            {
                "id": "rule_email_filter",
                "type": "email_security",
                "description": "Block emails with malicious attachments or suspicious links",
                "trigger": "malicious_attachment",
                "action": "quarantine",
                "enabled": True,
            },
            {
                "id": "rule_edr_ransomware",
                "type": "edr",
                "description": "Detect ransomware-like file encryption behavior",
                "trigger": "mass_file_encryption",
                "threshold": 50,
                "action": "kill_process_and_alert",
                "enabled": True,
            },
            {
                "id": "rule_smb_monitor",
                "type": "ids",
                "description": "Monitor for abnormal SMB lateral movement",
                "trigger": "smb_lateral_movement",
                "action": "alert",
                "enabled": True,
            },
            {
                "id": "rule_backup_protect",
                "type": "backup_protection",
                "description": "Protect backup server from unauthorized access",
                "trigger": "backup_access_anomaly",
                "action": "block_and_alert",
                "enabled": True,
            },
        ],
        "victory_conditions": {
            "red": {
                "primary": "Encrypt domain controller AD database",
                "secondary": "Encrypt file server and backup server before detection",
                "description": "Red Team wins by deploying ransomware on the domain controller.",
            },
            "blue": {
                "primary": "Detect and isolate all infected hosts before DC is compromised",
                "secondary": "Preserve backup integrity",
                "description": "Blue Team wins by containing the ransomware outbreak before critical systems are affected.",
            },
        },
    },
    "insider_threat": {
        "name": "insider_threat",
        "description": (
            "A malicious insider with legitimate access attempts to exfiltrate sensitive data "
            "and cover their tracks. The Blue Team must distinguish between normal user behavior "
            "and malicious activity using behavioral analytics."
        ),
        "difficulty": "hard",
        "network_topology": {
            "segments": [
                {
                    "name": "corporate",
                    "hosts": [
                        {"id": "insider-workstation", "role": "workstation", "os": "windows", "services": ["rdp", "smb"], "value": 3},
                        {"id": "hr-workstation", "role": "workstation", "os": "windows", "services": ["rdp"], "value": 3},
                        {"id": "finance-workstation", "role": "workstation", "os": "windows", "services": ["rdp"], "value": 5},
                    ],
                },
                {
                    "name": "data_stores",
                    "hosts": [
                        {"id": "hr-database", "role": "database", "os": "linux", "services": ["postgresql"], "value": 8},
                        {"id": "finance-database", "role": "database", "os": "linux", "services": ["oracle"], "value": 9},
                        {"id": "ip-repository", "role": "fileserver", "os": "windows", "services": ["smb", "sharepoint"], "value": 10},
                        {"id": "domain-controller", "role": "dc", "os": "windows", "services": ["ldap", "kerberos"], "value": 10},
                    ],
                },
                {
                    "name": "egress",
                    "hosts": [
                        {"id": "proxy-server", "role": "proxy", "os": "linux", "services": ["http", "https"], "value": 4},
                    ],
                },
            ],
            "firewall_rules": [
                {"from": "corporate", "to": "data_stores", "ports": [5432, 1521, 445, 389], "action": "allow"},
                {"from": "corporate", "to": "egress", "ports": [80, 443], "action": "allow"},
                {"from": "egress", "to": "internet", "ports": [443], "action": "allow"},
            ],
            "entry_points": ["insider-workstation"],
        },
        "initial_red_objectives": [
            {
                "id": "obj_reconnoiter",
                "phase": "recon",
                "description": "Map accessible data stores using legitimate credentials",
                "target_segment": "data_stores",
                "completed": False,
            },
            {
                "id": "obj_access_data",
                "phase": "exploit",
                "description": "Access and stage sensitive data from HR and finance databases",
                "target_hosts": ["hr-database", "finance-database", "ip-repository"],
                "completed": False,
            },
            {
                "id": "obj_exfil_data",
                "phase": "exfil",
                "description": "Exfiltrate data via the proxy server to external storage",
                "target_hosts": ["proxy-server"],
                "completed": False,
            },
            {
                "id": "obj_cover_tracks",
                "phase": "pivot",
                "description": "Modify or delete audit logs to cover malicious activity",
                "target_hosts": ["domain-controller"],
                "completed": False,
            },
        ],
        "initial_blue_rules": [
            {
                "id": "rule_ueba_01",
                "type": "ueba",
                "description": "Detect anomalous data access patterns compared to user baseline",
                "trigger": "abnormal_data_access_volume",
                "action": "alert",
                "enabled": True,
            },
            {
                "id": "rule_dlp_01",
                "type": "dlp",
                "description": "Block or alert on large data transfers to external destinations",
                "trigger": "large_outbound_transfer",
                "threshold_mb": 100,
                "action": "block_and_alert",
                "enabled": True,
            },
            {
                "id": "rule_audit_protection",
                "type": "siem",
                "description": "Alert on audit log deletion or modification attempts",
                "trigger": "audit_log_tampering",
                "action": "alert_and_restore",
                "enabled": True,
            },
        ],
        "victory_conditions": {
            "red": {
                "primary": "Exfiltrate sensitive data without triggering DLP controls",
                "secondary": "Cover tracks by modifying audit logs on domain controller",
                "description": "Red Team wins by successfully exfiltrating data and erasing evidence.",
            },
            "blue": {
                "primary": "Detect anomalous behavior and terminate insider session",
                "secondary": "Recover all exfiltrated data and preserve forensic evidence",
                "description": "Blue Team wins by catching the insider and preserving evidence for incident response.",
            },
        },
    },
}


def get_scenario(name: str) -> dict:
    scenario = SCENARIOS.get(name)
    if scenario is None:
        available = list(SCENARIOS.keys())
        raise ValueError(f"Scenario '{name}' not found. Available scenarios: {available}")
    return scenario


def list_scenarios() -> list[dict]:
    return [
        {
            "name": s["name"],
            "description": s["description"],
            "difficulty": s["difficulty"],
            "entry_points": s["network_topology"].get("entry_points", []),
            "red_objectives_count": len(s.get("initial_red_objectives", [])),
            "blue_rules_count": len(s.get("initial_blue_rules", [])),
            "victory_conditions": s.get("victory_conditions", {}),
        }
        for s in SCENARIOS.values()
    ]
