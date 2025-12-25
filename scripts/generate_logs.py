#!/usr/bin/env python3
"""
Generate synthetic logs for testing the AI SOC platform.
"""

import argparse
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import ipaddress
import hashlib


class LogGenerator:
    """Generates synthetic security logs."""
    
    def __init__(self, seed: Optional[int] = None):
        if seed:
            random.seed(seed)
        
        # Data pools
        self.usernames = [
            "admin", "root", "user1", "user2", "service_account",
            "backup", "www-data", "nobody", "postgres", "oracle"
        ]
        
        self.hostnames = [
            "webserver-01", "dbserver-01", "fileserver-01",
            "appserver-01", "gateway-01", "mailserver-01"
        ]
        
        self.processes = [
            "sshd", "nginx", "apache2", "mysql", "postgres",
            "bash", "python", "java", "systemd", "cron"
        ]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "curl/7.68.0",
            "python-requests/2.25.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        ]
        
        # Malicious IPs for testing
        self.malicious_ips = [
            "185.220.101.1", "185.220.101.2", "185.220.101.3",  # Tor exit nodes
            "192.168.1.100",  # Internal malicious
            "10.0.0.100",     # Internal malicious
        ]
        
        # Generate random IP ranges
        self.ip_pool = [str(ipaddress.IPv4Address(random.randint(1, 0xFFFFFFFF))) 
                       for _ in range(100)]
        
        # Common file paths
        self.file_paths = [
            "/etc/passwd", "/etc/shadow", "/var/log/auth.log",
            "/home/user/.ssh/id_rsa", "/var/www/html/index.php",
            "/tmp/malware.exe", "/bin/bash", "/usr/bin/python3"
        ]
        
        # Event types
        self.event_types = [
            "ssh_login", "ssh_failed", "http_request", "firewall_block",
            "process_execution", "file_access", "dns_query", "database_query"
        ]
    
    def generate_ssh_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate SSH login/failed event."""
        event_type = random.choice(["ssh_login", "ssh_failed"])
        
        if malicious and random.random() < 0.7:
            src_ip = random.choice(self.malicious_ips)
            username = random.choice(["root", "admin", "backup"])
        else:
            src_ip = random.choice(self.ip_pool)
            username = random.choice(self.usernames)
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": "192.168.1.10",  # Target server
            "src_port": random.randint(1024, 65535),
            "dst_port": 22,
            "user": username,
            "success": event_type == "ssh_login",
            "auth_method": random.choice(["password", "publickey"]),
            "session_id": hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            "hostname": random.choice(self.hostnames),
            "message": f"{'Accepted' if event_type == 'ssh_login' else 'Failed'} password for {username} from {src_ip} port {random.randint(1024, 65535)} ssh2",
        }
    
    def generate_http_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate HTTP request event."""
        if malicious:
            src_ip = random.choice(self.malicious_ips)
            paths = ["/admin.php", "/wp-login.php", "/shell.php", "/cmd.aspx"]
            status_code = random.choice([403, 404, 500])
            user_agent = "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        else:
            src_ip = random.choice(self.ip_pool)
            paths = ["/", "/index.html", "/api/v1/users", "/login", "/products"]
            status_code = random.choice([200, 201, 301, 302, 400, 404])
            user_agent = random.choice(self.user_agents)
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "http_request",
            "src_ip": src_ip,
            "dst_ip": "192.168.1.20",  # Web server
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 8080]),
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "path": random.choice(paths),
            "status_code": status_code,
            "bytes_sent": random.randint(100, 100000),
            "user_agent": user_agent,
            "referrer": random.choice(["", "https://google.com", "https://example.com"]),
            "hostname": random.choice(["webserver-01", "webserver-02"]),
            "message": f"{src_ip} - - [{datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET {random.choice(paths)} HTTP/1.1\" {status_code} {random.randint(100, 100000)}",
        }
    
    def generate_firewall_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate firewall block event."""
        if malicious:
            src_ip = random.choice(self.malicious_ips)
            dst_port = random.choice([22, 3389, 445, 1433, 3306])  # Common attack ports
            action = "DROP"
        else:
            src_ip = random.choice(self.ip_pool)
            dst_port = random.randint(1, 65535)
            action = random.choice(["ACCEPT", "DROP"])
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "firewall_block",
            "src_ip": src_ip,
            "dst_ip": random.choice(["192.168.1.1", "10.0.0.1"]),
            "src_port": random.randint(1024, 65535),
            "dst_port": dst_port,
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "action": action,
            "rule": f"INPUT_{dst_port}",
            "interface": random.choice(["eth0", "eth1", "wlan0"]),
            "hostname": random.choice(self.hostnames),
            "message": f"FW: {action} {src_ip}:{random.randint(1024, 65535)} -> {random.choice(['192.168.1.1', '10.0.0.1'])}:{dst_port} {random.choice(['TCP', 'UDP', 'ICMP'])}",
        }
    
    def generate_process_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate process execution event."""
        if malicious:
            process = random.choice(["malware.exe", "backdoor.sh", "miner.py", "ransomware"])
            parent_process = random.choice(["explorer.exe", "bash", "powershell"])
            user = "SYSTEM" if random.random() < 0.5 else "admin"
        else:
            process = random.choice(self.processes)
            parent_process = random.choice(["systemd", "bash", "cron", "init"])
            user = random.choice(self.usernames)
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "process_execution",
            "process_name": process,
            "process_id": random.randint(100, 9999),
            "parent_process": parent_process,
            "parent_pid": random.randint(1, 100),
            "user": user,
            "hostname": random.choice(self.hostnames),
            "command_line": f"{process} {random.choice(['--help', '-v', '--daemon', ''])}",
            "working_directory": random.choice(["/", "/home/user", "/tmp", "/var/www"]),
            "integrity_level": random.choice(["Low", "Medium", "High", "System"]),
            "message": f"Process {process} (PID: {random.randint(100, 9999)}) started by {user}",
        }
    
    def generate_file_access_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate file access event."""
        if malicious:
            file_path = random.choice(["/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys"])
            action = random.choice(["read", "write", "delete"])
            user = "root" if random.random() < 0.3 else random.choice(["backup", "www-data"])
        else:
            file_path = random.choice(self.file_paths)
            action = random.choice(["read", "write", "execute", "delete"])
            user = random.choice(self.usernames)
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "file_access",
            "file_path": file_path,
            "action": action,
            "user": user,
            "hostname": random.choice(self.hostnames),
            "process": random.choice(self.processes),
            "success": random.choice([True, False]),
            "permissions": random.choice(["rw-r--r--", "rwx------", "rw-rw-r--"]),
            "file_hash": hashlib.md5(file_path.encode()).hexdigest(),
            "message": f"File {action}: {file_path} by {user} via {random.choice(self.processes)}",
        }
    
    def generate_dns_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate DNS query event."""
        if malicious:
            domain = random.choice([
                "malware-c2.example.com", "phishing-site.net",
                "botnet-command.xyz", "data-exfil.tk"
            ])
            query_type = random.choice(["A", "AAAA", "TXT"])
            src_ip = random.choice(self.malicious_ips)
        else:
            domain = random.choice([
                "google.com", "github.com", "stackoverflow.com",
                "example.com", "microsoft.com", "amazon.com"
            ])
            query_type = random.choice(["A", "AAAA", "MX", "NS", "CNAME"])
            src_ip = random.choice(self.ip_pool)
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "dns_query",
            "src_ip": src_ip,
            "query": domain,
            "query_type": query_type,
            "response": random.choice(["192.168.1.100", "10.0.0.100", "NOERROR", "NXDOMAIN"]),
            "response_code": random.choice([0, 3]),
            "response_time_ms": random.randint(1, 1000),
            "dns_server": random.choice(["8.8.8.8", "1.1.1.1", "192.168.1.1"]),
            "hostname": random.choice(self.hostnames),
            "message": f"DNS query: {domain} ({query_type}) from {src_ip}",
        }
    
    def generate_database_event(self, malicious: bool = False) -> Dict[str, Any]:
        """Generate database query event."""
        if malicious:
            query = random.choice([
                "SELECT * FROM users WHERE 1=1",
                "DROP TABLE users",
                "INSERT INTO logs VALUES ('malicious data')",
                "UPDATE accounts SET balance = 1000000 WHERE user = 'attacker'"
            ])
            user = "admin" if random.random() < 0.5 else "attacker"
            database = "production_db"
        else:
            query = random.choice([
                "SELECT id, name FROM users WHERE active = 1",
                "INSERT INTO logs (message, timestamp) VALUES ('test', NOW())",
                "UPDATE products SET price = price * 1.1",
                "DELETE FROM temp_data WHERE created_at < NOW() - INTERVAL '7 days'"
            ])
            user = random.choice(self.usernames)
            database = random.choice(["production", "staging", "development"])
        
        return {
            "@timestamp": self._random_timestamp(),
            "event_type": "database_query",
            "user": user,
            "database": database,
            "query": query,
            "query_type": query.split()[0].upper(),
            "rows_affected": random.randint(0, 1000),
            "execution_time_ms": random.randint(1, 5000),
            "client_ip": random.choice(self.ip_pool),
            "hostname": random.choice(["dbserver-01", "dbserver-02"]),
            "application": random.choice(["webapp", "backend", "cronjob"]),
            "message": f"Database query by {user} on {database}: {query[:50]}...",
        }
    
    def generate_event(self, malicious_probability: float = 0.1) -> Dict[str, Any]:
        """Generate a random event."""
        malicious = random.random() < malicious_probability
        
        event_generators = [
            self.generate_ssh_event,
            self.generate_http_event,
            self.generate_firewall_event,
            self.generate_process_event,
            self.generate_file_access_event,
            self.generate_dns_event,
            self.generate_database_event,
        ]
        
        generator = random.choice(event_generators)
        event = generator(malicious)
        
        # Add common fields
        event["event_id"] = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
        event["severity"] = self._determine_severity(event, malicious)
        event["malicious"] = malicious
        
        # Add some noise/randomness
        if random.random() < 0.3:
            event["tags"] = random.sample(["prod", "test", "security", "audit"], random.randint(1, 3))
        
        return event
    
    def generate_brute_force_attack(self, count: int = 10) -> List[Dict[str, Any]]:
        """Generate a brute force attack sequence."""
        events = []
        src_ip = random.choice(self.malicious_ips)
        target_user = random.choice(["root", "admin", "ubuntu"])
        
        for i in range(count):
            event = self.generate_ssh_event(malicious=True)
            event["src_ip"] = src_ip
            event["user"] = target_user
            event["event_type"] = "ssh_failed"
            event["success"] = False
            
            # Space out the attempts
            base_time = datetime.utcnow() - timedelta(minutes=5)
            event_time = base_time + timedelta(seconds=i * random.randint(1, 10))
            event["@timestamp"] = event_time.isoformat() + "Z"
            
            events.append(event)
        
        # One successful login at the end
        if random.random() < 0.5:
            success_event = self.generate_ssh_event(malicious=True)
            success_event["src_ip"] = src_ip
            success_event["user"] = target_user
            success_event["event_type"] = "ssh_login"
            success_event["success"] = True
            success_event["@timestamp"] = (datetime.utcnow() - timedelta(minutes=4, seconds=30)).isoformat() + "Z"
            events.append(success_event)
        
        return events
    
    def generate_port_scan(self, count: int = 20) -> List[Dict[str, Any]]:
        """Generate a port scan sequence."""
        events = []
        src_ip = random.choice(self.malicious_ips)
        dst_ip = "192.168.1.100"
        
        ports = random.sample(range(1, 65535), min(count, 100))
        
        for i, port in enumerate(ports[:count]):
            event = self.generate_firewall_event(malicious=True)
            event["src_ip"] = src_ip
            event["dst_ip"] = dst_ip
            event["dst_port"] = port
            event["action"] = "DROP"
            
            # Space out the scans
            base_time = datetime.utcnow() - timedelta(minutes=2)
            event_time = base_time + timedelta(seconds=i * random.uniform(0.1, 0.5))
            event["@timestamp"] = event_time.isoformat() + "Z"
            
            events.append(event)
        
        return events
    
    def _random_timestamp(self) -> str:
        """Generate a random timestamp within the last 24 hours."""
        now = datetime.utcnow()
        random_offset = timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        return (now - random_offset).isoformat() + "Z"
    
    def _determine_severity(self, event: Dict[str, Any], malicious: bool) -> str:
        """Determine event severity."""
        if malicious:
            return random.choice(["high", "critical"])
        
        event_type = event.get("event_type", "")
        
        if event_type in ["ssh_failed", "firewall_block"]:
            return random.choice(["low", "medium"])
        elif event_type in ["ssh_login", "http_request"]:
            return "info"
        else:
            return "info"


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic logs for AI SOC platform testing")
    parser.add_argument(
        "--count",
        type=int,
        default=1000,
        help="Number of events to generate"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/raw/test_logs.jsonl",
        help="Output file path"
    )
    parser.add_argument(
        "--malicious-ratio",
        type=float,
        default=0.1,
        help="Ratio of malicious events (0.0 to 1.0)"
    )
    parser.add_argument(
        "--include-attacks",
        action="store_true",
        help="Include simulated attack sequences"
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Random seed for reproducibility"
    )
    
    args = parser.parse_args()
    
    # Create log generator
    generator = LogGenerator(seed=args.seed)
    
    # Generate events
    events = []
    
    # Add normal events
    for i in range(args.count):
        event = generator.generate_event(malicious_probability=args.malicious_ratio)
        events.append(event)
    
    # Add attack sequences if requested
    if args.include_attacks:
        print("Generating attack sequences...")
        
        # Brute force attack
        brute_force_events = generator.generate_brute_force_attack(count=15)
        events.extend(brute_force_events)
        print(f"  Added {len(brute_force_events)} brute force events")
        
        # Port scan
        port_scan_events = generator.generate_port_scan(count=25)
        events.extend(port_scan_events)
        print(f"  Added {len(port_scan_events)} port scan events")
        
        # Data exfiltration simulation
        for _ in range(3):
            exfil_event = generator.generate_http_event(malicious=True)
            exfil_event["bytes_sent"] = random.randint(1000000, 5000000)  # Large transfer
            exfil_event["path"] = "/api/data/export"
            events.append(exfil_event)
        print("  Added 3 data exfiltration events")
    
    # Write to file
    print(f"Writing {len(events)} events to {args.output}")
    
    import os
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    with open(args.output, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    
    # Statistics
    malicious_count = sum(1 for e in events if e.get("malicious", False))
    event_types = {}
    for event in events:
        event_type = event.get("event_type", "unknown")
        event_types[event_type] = event_types.get(event_type, 0) + 1
    
    print("\nStatistics:")
    print(f"  Total events: {len(events)}")
    print(f"  Malicious events: {malicious_count} ({malicious_count/len(events)*100:.1f}%)")
    print("  Event type distribution:")
    for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
        print(f"    {event_type}: {count} ({count/len(events)*100:.1f}%)")


if __name__ == "__main__":
    main()