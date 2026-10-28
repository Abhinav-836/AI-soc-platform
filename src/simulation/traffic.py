"""
Security-telemetry simulator.

A small company network (workstations, web/ssh/db servers, users) produces
normal traffic: web hits, DNS, outbound HTTPS, logins with the odd typo,
process starts, sudo, and background internet scanning noise.

Attack scenarios are injected as the *telemetry a SOC would receive* - not as
attack payloads. Web attacks arrive as WAF signature hits, malware as EDR
verdicts with a known-bad (placeholder) hash and beaconing to a known-bad
(placeholder) host, exfiltration as unusual byte volumes, and so on:

  brute_force          many failed SSH logins, sometimes ending in a success
  port_scan            dozens of ports probed, often followed by a web attack
  web_attack           repeated WAF signature hits from one client
  malware              EDR detection + periodic beaconing to a listed C2 host
  data_exfiltration    hundreds of MB uploaded to one external host
  dns_tunneling        bursts of long random sub-domains of one domain
  privilege_escalation EDR credential-access verdict + a new admin account

Attacker addresses come from the IETF documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and domains end in .example, so nothing here
points at a real system. Some of them are listed in
config/intel/sample_iocs.csv; the rest must be caught by rules or ML.

Every event carries `_truth` = {malicious, scenario, scenario_id}. The platform
strips it before storage and uses it only for the live scorecard.
"""
import ipaddress
import random
import string
import uuid
from typing import Any, Dict, List, Optional, Tuple

SCENARIOS = ("brute_force", "port_scan", "web_attack", "malware", "data_exfiltration", "dns_tunneling",
             "privilege_escalation")

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy"]
ADMINS = ["ops_admin", "svc_backup"]
WORKSTATIONS = [(f"ws-{i:02d}", f"10.10.1.{10 + i}") for i in range(1, 41)]
SERVERS = {
    "web": ("web-01", "10.10.2.10"), "bastion": ("bastion-01", "10.10.2.15"), "db": ("db-01", "10.10.2.20"),
    "dc": ("dc-01", "10.10.2.5"), "mail": ("mail-01", "10.10.2.30"), "file": ("file-01", "10.10.2.40"),
}
NORMAL_DOMAINS = ["google.com", "microsoft.com", "office365.com", "github.com", "slack.com", "zoom.us",
                  "aws.amazon.com", "cloudflare.com", "wikipedia.org", "stackoverflow.com", "linkedin.com",
                  "windowsupdate.com", "apple.com", "npmjs.org", "pypi.org"]
NORMAL_PATHS = ["/", "/index.html", "/products", "/products/42", "/cart", "/login", "/api/v1/items",
                "/api/v1/items?page=2", "/static/app.js", "/static/style.css", "/about", "/contact",
                "/search?q=laptop", "/blog/security-tips", "/images/logo.png"]
NORMAL_PROCESSES = ["chrome.exe", "outlook.exe", "teams.exe", "code.exe", "explorer.exe", "python.exe",
                    "excel.exe", "svchost.exe"]
SERVER_PROCESSES = ["nginx", "postgres", "cron", "bash", "sshd"]
WAF_SIGNATURES = ["sql_injection", "cross_site_scripting", "path_traversal", "command_injection"]

C2_IPS = ["192.0.2.66", "192.0.2.67"]                                  # listed in sample_iocs.csv
C2_DOMAINS = ["update-check.evil-cdn.example", "cdn.badupdate.example"]  # listed
MALWARE_HASH = "e99a18c428cb38d5f260853678922e03"                      # listed placeholder hash
TUNNEL_DOMAIN = "t.dnsx-tunnel.example"                                # not listed: rules/ML must catch it
EXFIL_HOST = "198.51.100.200"                                          # not listed


def _public_ip(rng: random.Random) -> str:
    while True:
        ip = ipaddress.IPv4Address(rng.randint(0x01000000, 0xDFFFFFFF))
        if ip.is_global and not any(ip in ipaddress.ip_network(n) for n in
                                    ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")):
            return str(ip)


class TrafficGenerator:
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.clients = [_public_ip(self.rng) for _ in range(300)]
        self.cloud = [_public_ip(self.rng) for _ in range(40)]
        self.noise = [_public_ip(self.rng) for _ in range(200)]

    # ------------------------------------------------------------------ normal
    def normal_event(self) -> Dict[str, Any]:
        r = self.rng.random()
        if r < 0.38:
            e = self._http()
        elif r < 0.58:
            e = self._dns()
        elif r < 0.73:
            e = self._outbound()
        elif r < 0.81:
            e = self._login()
        elif r < 0.92:
            e = self._process()
        elif r < 0.97:
            e = self._noise_drop()
        else:
            e = self._sudo()
        e["_truth"] = {"malicious": False, "scenario": "normal", "scenario_id": None}
        return e

    def _http(self):
        rng = self.rng
        host, ip = SERVERS["web"]
        return {"event_type": "http_request", "src_ip": rng.choice(self.clients), "dst_ip": ip, "dst_port": 443,
                "hostname": host, "http_method": rng.choice(["GET"] * 8 + ["POST"]), "url": rng.choice(NORMAL_PATHS),
                "status_code": rng.choices([200, 304, 301, 404, 401, 500], [80, 6, 4, 6, 3, 1])[0],
                "bytes_out": rng.randint(400, 90000)}

    def _dns(self):
        host, ip = self.rng.choice(WORKSTATIONS)
        sub = self.rng.choice(["", "www.", "api.", "login.", "cdn."])
        return {"event_type": "dns_query", "src_ip": ip, "dst_ip": SERVERS["dc"][1], "dst_port": 53, "hostname": host,
                "query": sub + self.rng.choice(NORMAL_DOMAINS), "protocol": "udp"}

    def _outbound(self):
        host, ip = self.rng.choice(WORKSTATIONS)
        big = self.rng.random() < 0.01  # legit large upload (cloud backup, video call)
        return {"event_type": "network_connection", "src_ip": ip, "dst_ip": self.rng.choice(self.cloud),
                "dst_port": self.rng.choice([443] * 9 + [80]), "hostname": host, "protocol": "tcp", "action": "allow",
                "bytes_out": self.rng.randint(5_000_000, 25_000_000) if big else self.rng.randint(800, 250_000),
                "bytes_in": self.rng.randint(2_000, 2_000_000)}

    def _login(self):
        host, ip = self.rng.choice(WORKSTATIONS)
        typo = self.rng.random() < 0.12  # people mistype passwords
        b_host, b_ip = SERVERS["bastion"]
        return {"event_type": "ssh_failed" if typo else "ssh_accepted", "src_ip": ip, "dst_ip": b_ip,
                "dst_port": 22, "hostname": b_host, "user": self.rng.choice(USERS + ADMINS)}

    def _process(self):
        if self.rng.random() < 0.75:
            host, ip = self.rng.choice(WORKSTATIONS)
            name, parent = self.rng.choice(NORMAL_PROCESSES), "explorer.exe"
        else:
            host, ip = self.rng.choice(list(SERVERS.values()))
            name, parent = self.rng.choice(SERVER_PROCESSES), "systemd"
        return {"event_type": "process_execution", "hostname": host, "src_ip": ip, "user": self.rng.choice(USERS),
                "process_name": name, "parent_process": parent, "edr_verdict": "clean"}

    def _noise_drop(self):
        host, ip = self.rng.choice(list(SERVERS.values()))
        return {"event_type": "firewall_drop", "src_ip": self.rng.choice(self.noise), "dst_ip": ip,
                "dst_port": self.rng.choice([23, 445, 3389, 22, 1433, 5900, 8080]), "protocol": "tcp",
                "action": "deny", "hostname": host}

    def _sudo(self):
        host, ip = self.rng.choice([SERVERS["web"], SERVERS["db"], SERVERS["bastion"]])
        return {"event_type": "sudo_command", "hostname": host, "src_ip": ip, "user": self.rng.choice(ADMINS),
                "command_line": self.rng.choice(["apt update", "systemctl restart nginx", "journalctl -u nginx"])}

    # ------------------------------------------------------------------ attacks
    def attack(self, scenario: Optional[str] = None) -> Tuple[str, str, List[Tuple[float, Dict[str, Any]]]]:
        """Returns (scenario, scenario_id, [(delay_seconds, event), ...])."""
        scenario = scenario or self.rng.choice(SCENARIOS)
        if scenario not in SCENARIOS:
            raise ValueError(f"Unknown scenario {scenario}; choose from {SCENARIOS}")
        sid = "SCN-" + uuid.uuid4().hex[:8]
        steps = getattr(self, f"_{scenario}")()
        for _, e in steps:
            e["_truth"] = {"malicious": True, "scenario": scenario, "scenario_id": sid}
        return scenario, sid, steps

    def _attacker(self, listed: bool = False) -> str:
        # 203.0.113.0/25 is in the sample IOC list; 198.51.100.x is not
        return f"203.0.113.{self.rng.randint(10, 120)}" if listed else f"198.51.100.{self.rng.randint(10, 190)}"

    def _brute_force(self):
        rng, attacker = self.rng, self._attacker()
        host, ip = SERVERS["bastion"]
        steps, t = [], 0.0
        for _ in range(rng.randint(12, 35)):
            t += rng.uniform(0.3, 2.0)
            steps.append((t, {"event_type": "ssh_failed", "src_ip": attacker, "dst_ip": ip, "dst_port": 22,
                              "hostname": host, "user": rng.choice(["root", "admin", "test", "ubuntu"] + ADMINS)}))
        if rng.random() < 0.4:  # a guess succeeded
            t += rng.uniform(2, 6)
            steps.append((t, {"event_type": "ssh_accepted", "src_ip": attacker, "dst_ip": ip, "dst_port": 22,
                              "hostname": host, "user": "svc_backup"}))
        return steps

    def _port_scan(self):
        rng = self.rng
        attacker = self._attacker(listed=rng.random() < 0.5)
        host, ip = SERVERS["web"]
        ports = rng.sample(range(1, 10000), rng.randint(15, 40))
        steps, t = [], 0.0
        for port in ports:
            t += rng.uniform(0.05, 0.4)
            steps.append((t, {"event_type": "firewall_drop", "src_ip": attacker, "dst_ip": ip, "dst_port": port,
                              "protocol": "tcp", "action": "deny", "hostname": host}))
        if rng.random() < 0.5:
            for delay, e in self._web_attack(attacker):
                steps.append((t + 3 + delay, e))
        return steps

    def _web_attack(self, attacker: Optional[str] = None):
        rng = self.rng
        attacker = attacker or self._attacker(listed=rng.random() < 0.3)
        host, ip = SERVERS["web"]
        signature = rng.choice(WAF_SIGNATURES)
        steps, t = [], 0.0
        for _ in range(rng.randint(4, 12)):
            t += rng.uniform(0.2, 1.5)
            steps.append((t, {"event_type": "waf_alert", "src_ip": attacker, "dst_ip": ip, "dst_port": 443,
                              "hostname": host, "url": rng.choice(NORMAL_PATHS), "waf_signature": signature,
                              "action": rng.choice(["blocked", "logged"]), "status_code": rng.choice([403, 200])}))
        return steps

    def _malware(self):
        rng = self.rng
        host, ip = rng.choice(WORKSTATIONS)
        c2_ip, c2_domain = rng.choice(C2_IPS), rng.choice(C2_DOMAINS)
        steps = [(0.0, {"event_type": "process_execution", "hostname": host, "src_ip": ip, "user": rng.choice(USERS),
                        "process_name": "invoice_viewer.exe", "parent_process": "outlook.exe",
                        "file_hash": MALWARE_HASH, "edr_verdict": "malicious", "edr_category": "trojan"}),
                 (1.0, {"event_type": "dns_query", "src_ip": ip, "dst_ip": SERVERS["dc"][1], "dst_port": 53,
                        "hostname": host, "query": c2_domain})]
        t = 2.0
        for _ in range(rng.randint(4, 8)):  # regular beaconing
            t += 5 + rng.uniform(-0.5, 0.5)
            steps.append((t, {"event_type": "network_connection", "src_ip": ip, "dst_ip": c2_ip, "dst_port": 443,
                              "hostname": host, "protocol": "tcp", "action": "allow",
                              "bytes_out": rng.randint(300, 900), "bytes_in": rng.randint(200, 600)}))
        return steps

    def _data_exfiltration(self):
        rng = self.rng
        host, ip = rng.choice(WORKSTATIONS)
        steps, t = [], 0.0
        for _ in range(rng.randint(4, 8)):
            t += rng.uniform(1, 4)
            steps.append((t, {"event_type": "network_connection", "src_ip": ip, "dst_ip": EXFIL_HOST, "dst_port": 443,
                              "hostname": host, "protocol": "tcp", "action": "allow",
                              "bytes_out": rng.randint(40_000_000, 90_000_000), "bytes_in": rng.randint(5_000, 50_000)}))
        return steps

    def _dns_tunneling(self):
        rng = self.rng
        host, ip = rng.choice(WORKSTATIONS)
        steps, t = [], 0.0
        for _ in range(rng.randint(20, 40)):
            t += rng.uniform(0.1, 0.6)
            label = "".join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(35, 55)))
            steps.append((t, {"event_type": "dns_query", "src_ip": ip, "dst_ip": SERVERS["dc"][1], "dst_port": 53,
                              "hostname": host, "query": f"{label}.{TUNNEL_DOMAIN}", "query_type": "TXT"}))
        return steps

    def _privilege_escalation(self):
        rng = self.rng
        host, ip = SERVERS["db"]
        user = rng.choice(USERS)
        return [
            (0.0, {"event_type": "process_execution", "hostname": host, "src_ip": ip, "user": user,
                   "process_name": "unknown_tool", "edr_verdict": "malicious", "edr_category": "credential_access"}),
            (2.0, {"event_type": "user_created", "hostname": host, "src_ip": ip, "user": user,
                   "new_user": "support_" + "".join(rng.choices(string.digits, k=3))}),
            (3.0, {"event_type": "group_change", "hostname": host, "src_ip": ip, "user": user,
                   "group": "sudo", "change": "member_added"}),
        ]


def generate_dataset(n_normal: int = 5000, n_attacks: int = 20, seed: Optional[int] = None,
                     start=None, rate: float = 5.0) -> List[Dict[str, Any]]:
    """Offline dataset (time-ordered) for log files, training and evaluation."""
    from datetime import timedelta
    from src.core.time_utils import iso, utcnow

    gen = TrafficGenerator(seed)
    start = start or utcnow() - timedelta(seconds=n_normal / rate)
    events: List[Tuple[float, Dict[str, Any]]] = []
    span = n_normal / rate
    for i in range(n_normal):
        events.append((i / rate, gen.normal_event()))
    for _ in range(n_attacks):
        offset = gen.rng.uniform(0, max(span - 60, 1))
        _, _, steps = gen.attack()
        events.extend((offset + d, e) for d, e in steps)
    events.sort(key=lambda x: x[0])
    out = []
    for offset, e in events:
        e["@timestamp"] = iso(start + timedelta(seconds=offset))
        out.append(e)
    return out
