from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
import copy


@dataclass
class Vulnerability:
    cve_id: str
    name: str
    description: str
    cvss_score: float
    mitre_technique: str
    mitre_tactic: str
    exploitable: bool = True
    patched: bool = False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "cvss_score": self.cvss_score,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "exploitable": self.exploitable,
            "patched": self.patched,
        }


@dataclass
class Service:
    name: str
    port: int
    protocol: str
    version: str
    banner: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "version": self.version,
            "banner": self.banner,
        }


@dataclass
class Host:
    ip: str
    hostname: str
    os: str
    services: List[Service] = field(default_factory=list)
    patch_level: int = 5
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    compromise_status: str = "none"  # none / foothold / owned
    firewall_rules: List[str] = field(default_factory=list)
    is_isolated: bool = False
    logs: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "services": [s.to_dict() for s in self.services],
            "patch_level": self.patch_level,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "compromise_status": self.compromise_status,
            "firewall_rules": self.firewall_rules,
            "is_isolated": self.is_isolated,
            "logs": self.logs[-20:],
        }

    def get_exploitable_vulns(self) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.exploitable and not v.patched]

    def patch_vulnerability(self, cve_id: str) -> bool:
        for vuln in self.vulnerabilities:
            if vuln.cve_id == cve_id:
                vuln.patched = True
                vuln.exploitable = False
                return True
        return False


# Connection map: which hosts can reach which
CONNECTION_MAP: Dict[str, List[str]] = {
    "web-server": ["db-server", "mail-server", "internal-workstation"],
    "db-server": ["web-server"],
    "mail-server": ["web-server", "internal-workstation"],
    "internal-workstation": ["domain-controller", "web-server", "mail-server"],
    "domain-controller": ["internal-workstation", "db-server"],
}


def _build_initial_hosts() -> Dict[str, Host]:
    hosts: Dict[str, Host] = {}

    # --- web-server ---
    hosts["web-server"] = Host(
        ip="10.0.0.10",
        hostname="web-server",
        os="Linux (Ubuntu 20.04)",
        patch_level=3,
        services=[
            Service("http", 80, "tcp", "Apache/2.4.49", "Apache/2.4.49 (Ubuntu)"),
            Service("https", 443, "tcp", "Apache/2.4.49", "Apache/2.4.49 (Ubuntu)"),
            Service("ssh", 22, "tcp", "OpenSSH 7.9", "SSH-2.0-OpenSSH_7.9"),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2021-41773",
                name="Apache Path Traversal / RCE",
                description=(
                    "A flaw in path normalization in Apache HTTP Server 2.4.49 "
                    "allows an attacker to map URLs to files outside the document root. "
                    "If CGI scripts are enabled, this can lead to RCE."
                ),
                cvss_score=9.8,
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
            ),
            Vulnerability(
                cve_id="CVE-2021-42013",
                name="Apache Path Traversal (bypass fix)",
                description=(
                    "Incomplete fix for CVE-2021-41773 in Apache 2.4.50 still allows "
                    "path traversal and potential RCE via mod_cgi."
                ),
                cvss_score=9.8,
                mitre_technique="T1059.004",
                mitre_tactic="Execution",
            ),
            Vulnerability(
                cve_id="CVE-2021-26855",
                name="Weak SSH key rotation",
                description="SSH host keys have not been rotated; brute-force risk via leaked credentials.",
                cvss_score=5.3,
                mitre_technique="T1110.001",
                mitre_tactic="Credential Access",
            ),
        ],
        firewall_rules=["ALLOW 0.0.0.0/0 -> 80/tcp", "ALLOW 0.0.0.0/0 -> 443/tcp", "ALLOW 10.0.0.0/24 -> 22/tcp"],
    )

    # --- db-server ---
    hosts["db-server"] = Host(
        ip="10.0.0.20",
        hostname="db-server",
        os="Linux (CentOS 7)",
        patch_level=5,
        services=[
            Service("postgresql", 5432, "tcp", "PostgreSQL 12.8", ""),
            Service("mysql", 3306, "tcp", "MySQL 5.7.36", ""),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2019-10164",
                name="PostgreSQL Stack Overflow",
                description=(
                    "PostgreSQL versions before 11.3 are vulnerable to a stack-based "
                    "buffer overflow via a crafted SQL function."
                ),
                cvss_score=8.8,
                mitre_technique="T1210",
                mitre_tactic="Lateral Movement",
            ),
            Vulnerability(
                cve_id="CVE-2012-2122",
                name="MySQL Authentication Bypass",
                description=(
                    "A timing flaw in MySQL/MariaDB authentication allows bypassing "
                    "password checks given enough retries."
                ),
                cvss_score=5.1,
                mitre_technique="T1078",
                mitre_tactic="Defense Evasion",
            ),
        ],
        firewall_rules=["ALLOW 10.0.0.10/32 -> 5432/tcp", "ALLOW 10.0.0.10/32 -> 3306/tcp"],
    )

    # --- mail-server ---
    hosts["mail-server"] = Host(
        ip="10.0.0.30",
        hostname="mail-server",
        os="Linux (Debian 10)",
        patch_level=6,
        services=[
            Service("smtp", 25, "tcp", "Postfix 3.4.14", "220 mail-server ESMTP Postfix"),
            Service("submission", 587, "tcp", "Postfix 3.4.14", "220 mail-server ESMTP"),
            Service("imaps", 993, "tcp", "Dovecot 2.3.13", ""),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2020-7247",
                name="OpenSMTPD Remote Code Execution",
                description=(
                    "A flaw in OpenSMTPD's smtp_mailaddr() allows an attacker to "
                    "execute arbitrary commands with root privileges."
                ),
                cvss_score=10.0,
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                exploitable=False,  # patched on this host
                patched=True,
            ),
            Vulnerability(
                cve_id="CVE-2021-20323",
                name="Postfix SMTP Header Injection",
                description="Improper sanitization of SMTP headers may allow email spoofing.",
                cvss_score=4.3,
                mitre_technique="T1566.002",
                mitre_tactic="Initial Access",
            ),
        ],
        firewall_rules=[
            "ALLOW 0.0.0.0/0 -> 25/tcp",
            "ALLOW 10.0.0.0/24 -> 587/tcp",
            "ALLOW 10.0.0.0/24 -> 993/tcp",
        ],
    )

    # --- internal-workstation ---
    hosts["internal-workstation"] = Host(
        ip="10.0.0.40",
        hostname="internal-workstation",
        os="Windows 10 (Build 19041)",
        patch_level=2,
        services=[
            Service("smb", 445, "tcp", "SMB 1.0/CIFS", ""),
            Service("rdp", 3389, "tcp", "RDP 10.0", ""),
            Service("msrpc", 135, "tcp", "MSRPC", ""),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2017-0144",
                name="EternalBlue SMB RCE (MS17-010)",
                description=(
                    "A critical vulnerability in Microsoft SMBv1 allows a remote attacker "
                    "to execute arbitrary code. Exploited by WannaCry and NotPetya."
                ),
                cvss_score=9.3,
                mitre_technique="T1210",
                mitre_tactic="Lateral Movement",
            ),
            Vulnerability(
                cve_id="CVE-2019-0708",
                name="BlueKeep RDP RCE",
                description=(
                    "A remote code execution vulnerability in Remote Desktop Services "
                    "allows unauthenticated attackers to execute code via RDP."
                ),
                cvss_score=9.8,
                mitre_technique="T1210",
                mitre_tactic="Lateral Movement",
            ),
            Vulnerability(
                cve_id="CVE-2021-34527",
                name="PrintNightmare",
                description=(
                    "A flaw in the Windows Print Spooler service allows remote code execution "
                    "and local privilege escalation."
                ),
                cvss_score=8.8,
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
            ),
        ],
        firewall_rules=["ALLOW 10.0.0.0/24 -> 445/tcp", "ALLOW 10.0.0.0/24 -> 3389/tcp"],
    )

    # --- domain-controller ---
    hosts["domain-controller"] = Host(
        ip="10.0.0.100",
        hostname="domain-controller",
        os="Windows Server 2019",
        patch_level=4,
        services=[
            Service("ldap", 389, "tcp", "Active Directory LDAP", ""),
            Service("ldaps", 636, "tcp", "Active Directory LDAPS", ""),
            Service("gc", 3268, "tcp", "AD Global Catalog", ""),
            Service("kerberos", 88, "tcp", "Kerberos 5", ""),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2020-1472",
                name="Zerologon",
                description=(
                    "A privilege escalation vulnerability in Netlogon Remote Protocol (MS-NRPC) "
                    "allows an unauthenticated attacker to become domain admin in ~3 seconds."
                ),
                cvss_score=10.0,
                mitre_technique="T1484.001",
                mitre_tactic="Defense Evasion",
            ),
            Vulnerability(
                cve_id="CVE-2021-42278",
                name="sAMAccountName Spoofing (noPac)",
                description=(
                    "Allows privilege escalation from regular domain user to domain admin "
                    "via manipulation of the sAMAccountName attribute."
                ),
                cvss_score=8.8,
                mitre_technique="T1134.005",
                mitre_tactic="Privilege Escalation",
            ),
            Vulnerability(
                cve_id="CVE-2022-26923",
                name="AD CS Certificate Spoofing",
                description=(
                    "Active Directory Certificate Services mishandles certificate requests, "
                    "allowing privilege escalation to domain admin."
                ),
                cvss_score=8.8,
                mitre_technique="T1649",
                mitre_tactic="Credential Access",
            ),
        ],
        firewall_rules=[
            "ALLOW 10.0.0.0/24 -> 389/tcp",
            "ALLOW 10.0.0.0/24 -> 636/tcp",
            "ALLOW 10.0.0.0/24 -> 88/tcp",
        ],
    )

    return hosts


class NetworkState:
    def __init__(self):
        self.hosts: Dict[str, Host] = _build_initial_hosts()
        self.connection_map: Dict[str, List[str]] = copy.deepcopy(CONNECTION_MAP)

        # Red team knowledge: mapping hostname -> list of discovered facts
        self.red_team_knowledge: Dict[str, List[str]] = {}

        # Blue team alerts
        self.alerts: List[Dict[str, Any]] = []

        self.turn_counter: int = 0
        self.game_status: str = "idle"  # idle / running / red_wins / blue_wins

        # Firewall blocks: set of rule strings like "BLOCK 10.0.0.10/32 -> 10.0.0.20:5432"
        self.firewall_blocks: Set[str] = set()

        self.created_at: str = datetime.utcnow().isoformat()

    # ------------------------------------------------------------------ #
    #  Host helpers                                                        #
    # ------------------------------------------------------------------ #

    def get_host(self, hostname: str) -> Optional[Host]:
        return self.hosts.get(hostname)

    def update_compromise(self, hostname: str, status: str) -> bool:
        """Update the compromise status of a host. Returns True on success."""
        host = self.get_host(hostname)
        if host is None:
            return False
        valid_statuses = {"none", "foothold", "owned"}
        if status not in valid_statuses:
            return False
        host.compromise_status = status
        host.logs.append(
            f"[{datetime.utcnow().isoformat()}] Compromise status changed to '{status}'"
        )
        self._check_win_condition()
        return True

    def isolate_host(self, hostname: str) -> bool:
        """Blue team action: isolate a host from the network."""
        host = self.get_host(hostname)
        if host is None:
            return False
        host.is_isolated = True
        host.logs.append(f"[{datetime.utcnow().isoformat()}] Host isolated by blue team")
        # Remove it from connection map
        for src, targets in self.connection_map.items():
            if hostname in targets:
                targets.remove(hostname)
        self.connection_map[hostname] = []
        return True

    # ------------------------------------------------------------------ #
    #  Alerts                                                              #
    # ------------------------------------------------------------------ #

    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add a security alert. Expected keys: severity, source, target, message, technique."""
        alert.setdefault("timestamp", datetime.utcnow().isoformat())
        alert.setdefault("severity", "medium")
        alert.setdefault("acknowledged", False)
        self.alerts.append(alert)

    def acknowledge_alert(self, index: int) -> bool:
        if 0 <= index < len(self.alerts):
            self.alerts[index]["acknowledged"] = True
            return True
        return False

    # ------------------------------------------------------------------ #
    #  Firewall                                                            #
    # ------------------------------------------------------------------ #

    def add_firewall_block(self, rule: str) -> None:
        """Add a firewall blocking rule, e.g. 'BLOCK 10.0.0.10/32 -> 10.0.0.20:5432'."""
        self.firewall_blocks.add(rule)

    def is_connection_blocked(self, src_ip: str, dst_ip: str, port: Optional[int] = None) -> bool:
        """Check if a connection is blocked by any firewall rule."""
        for rule in self.firewall_blocks:
            rule_lower = rule.lower()
            if src_ip in rule_lower and dst_ip in rule_lower:
                if port is None:
                    return True
                if str(port) in rule_lower:
                    return True
        return False

    def can_reach(self, src_hostname: str, dst_hostname: str) -> bool:
        """Check if src can reach dst based on connection map and isolation."""
        src_host = self.get_host(src_hostname)
        dst_host = self.get_host(dst_hostname)
        if src_host is None or dst_host is None:
            return False
        if src_host.is_isolated or dst_host.is_isolated:
            return False
        return dst_hostname in self.connection_map.get(src_hostname, [])

    # ------------------------------------------------------------------ #
    #  Turn & win condition                                                #
    # ------------------------------------------------------------------ #

    def advance_turn(self) -> None:
        self.turn_counter += 1
        self._check_win_condition()

    def _check_win_condition(self) -> None:
        if self.game_status != "running":
            return

        # Red wins if domain-controller is owned
        dc = self.get_host("domain-controller")
        if dc and dc.compromise_status == "owned":
            self.game_status = "red_wins"
            return

        # Red wins if 3+ hosts are owned
        owned = sum(1 for h in self.hosts.values() if h.compromise_status == "owned")
        if owned >= 3:
            self.game_status = "red_wins"
            return

        # Blue wins if all red-team-known compromised hosts are isolated or cleaned
        compromised = [
            h for h in self.hosts.values()
            if h.compromise_status in ("foothold", "owned")
        ]
        if self.turn_counter > 5 and len(compromised) == 0:
            self.game_status = "blue_wins"

    # ------------------------------------------------------------------ #
    #  Red team knowledge                                                  #
    # ------------------------------------------------------------------ #

    def add_red_knowledge(self, hostname: str, fact: str) -> None:
        if hostname not in self.red_team_knowledge:
            self.red_team_knowledge[hostname] = []
        if fact not in self.red_team_knowledge[hostname]:
            self.red_team_knowledge[hostname].append(fact)

    def get_red_knowledge(self, hostname: str) -> List[str]:
        return self.red_team_knowledge.get(hostname, [])

    # ------------------------------------------------------------------ #
    #  Serialization & summaries                                           #
    # ------------------------------------------------------------------ #

    def get_state_summary(self) -> dict:
        """Return a concise dict suitable for LLM context window."""
        summary = {
            "turn": self.turn_counter,
            "game_status": self.game_status,
            "hosts": [],
            "recent_alerts": self.alerts[-5:],
            "firewall_blocks": list(self.firewall_blocks),
        }
        for name, host in self.hosts.items():
            reachable_from = [
                src for src, targets in self.connection_map.items()
                if name in targets
            ]
            summary["hosts"].append(
                {
                    "hostname": name,
                    "ip": host.ip,
                    "os": host.os,
                    "compromise_status": host.compromise_status,
                    "patch_level": host.patch_level,
                    "is_isolated": host.is_isolated,
                    "open_ports": [s.port for s in host.services],
                    "exploitable_vulns": [
                        {"cve": v.cve_id, "name": v.name, "cvss": v.cvss_score, "technique": v.mitre_technique}
                        for v in host.get_exploitable_vulns()
                    ],
                    "reachable_from": reachable_from,
                    "can_reach": self.connection_map.get(name, []),
                }
            )
        return summary

    def get_full_state(self) -> dict:
        """Return the full state as a dict for SSE streaming to the frontend."""
        return {
            "turn": self.turn_counter,
            "game_status": self.game_status,
            "created_at": self.created_at,
            "hosts": {name: host.to_dict() for name, host in self.hosts.items()},
            "connection_map": self.connection_map,
            "red_team_knowledge": self.red_team_knowledge,
            "alerts": self.alerts,
            "firewall_blocks": list(self.firewall_blocks),
            "stats": self._compute_stats(),
        }

    def _compute_stats(self) -> dict:
        total = len(self.hosts)
        compromised = sum(1 for h in self.hosts.values() if h.compromise_status != "none")
        owned = sum(1 for h in self.hosts.values() if h.compromise_status == "owned")
        footholds = sum(1 for h in self.hosts.values() if h.compromise_status == "foothold")
        isolated = sum(1 for h in self.hosts.values() if h.is_isolated)
        total_vulns = sum(len(h.vulnerabilities) for h in self.hosts.values())
        exploitable_vulns = sum(len(h.get_exploitable_vulns()) for h in self.hosts.values())
        return {
            "total_hosts": total,
            "compromised_hosts": compromised,
            "owned_hosts": owned,
            "foothold_hosts": footholds,
            "isolated_hosts": isolated,
            "total_vulnerabilities": total_vulns,
            "exploitable_vulnerabilities": exploitable_vulns,
            "total_alerts": len(self.alerts),
            "unacknowledged_alerts": sum(1 for a in self.alerts if not a.get("acknowledged")),
            "firewall_rules_active": len(self.firewall_blocks),
        }

    def to_dict(self) -> dict:
        """Full JSON-serializable representation."""
        return self.get_full_state()

    def reset(self) -> None:
        """Reset the simulation to initial state."""
        self.__init__()
