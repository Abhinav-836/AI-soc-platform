#!/usr/bin/env python3
"""
Replay attack scenarios for testing detection capabilities.
"""

import argparse
import json
import time
import random
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import requests
import sys


class AttackReplayer:
    """Replays attack scenarios for testing."""
    
    def __init__(self, api_url: str = "http://localhost:8080"):
        self.api_url = api_url
    
    async def replay_brute_force(
        self,
        target_ip: str = "192.168.1.10",
        attacker_ip: str = "185.220.101.1",
        duration_minutes: int = 5,
        attempts_per_minute: int = 20,
    ):
        """Replay SSH brute force attack."""
        print(f"Replaying brute force attack from {attacker_ip} to {target_ip}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        usernames = ["root", "admin", "ubuntu", "test", "user"]
        passwords = ["password", "123456", "admin", "test", "root"]
        
        attempt_count = 0
        success_count = 0
        
        while datetime.utcnow() < end_time:
            # Generate failed attempts
            attempts_this_minute = random.randint(
                attempts_per_minute // 2,
                attempts_per_minute * 2
            )
            
            for i in range(attempts_this_minute):
                username = random.choice(usernames)
                password = random.choice(passwords)
                
                # Simulate SSH attempt
                event = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "ssh_failed",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": 22,
                    "user": username,
                    "success": False,
                    "auth_method": "password",
                    "message": f"Failed password for {username} from {attacker_ip} port {random.randint(1024, 65535)} ssh2",
                    "hostname": "webserver-01",
                }
                
                # Send to SOC platform
                await self._send_event(event)
                
                attempt_count += 1
                
                # Small delay between attempts
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Chance of successful login
            if random.random() < 0.1 and success_count == 0:
                username = random.choice(["root", "admin"])
                event = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "ssh_login",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": 22,
                    "user": username,
                    "success": True,
                    "auth_method": "password",
                    "message": f"Accepted password for {username} from {attacker_ip} port {random.randint(1024, 65535)} ssh2",
                    "hostname": "webserver-01",
                }
                
                await self._send_event(event)
                success_count += 1
                print(f"  Successful login as {username}")
            
            # Wait for next minute
            remaining_time = (end_time - datetime.utcnow()).total_seconds()
            if remaining_time > 60:
                await asyncio.sleep(60)
            else:
                await asyncio.sleep(remaining_time)
        
        print(f"Brute force attack completed: {attempt_count} attempts, {success_count} successes")
    
    async def replay_port_scan(
        self,
        target_ip: str = "192.168.1.100",
        attacker_ip: str = "192.168.101.2",
        duration_minutes: int = 2,
        ports_per_second: int = 10,
    ):
        """Replay port scan attack."""
        print(f"Replaying port scan from {attacker_ip} to {target_ip}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
            445, 993, 995, 1723, 3306, 3389, 5900, 8080
        ]
        
        # Add some random ports
        all_ports = common_ports + random.sample(range(1, 65535), 50)
        
        scan_count = 0
        
        while datetime.utcnow() < end_time:
            # Scan batch of ports
            ports_to_scan = random.sample(all_ports, min(ports_per_second, len(all_ports)))
            
            for port in ports_to_scan:
                # Simulate firewall block
                event = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "firewall_block",
                    "src_ip": attacker_ip,
                    "dst_ip": target_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": port,
                    "protocol": random.choice(["TCP", "UDP"]),
                    "action": "DROP",
                    "rule": f"INPUT_{port}",
                    "interface": "eth0",
                    "hostname": "firewall-01",
                    "message": f"FW: DROP {attacker_ip}:{random.randint(1024, 65535)} -> {target_ip}:{port} {random.choice(['TCP', 'UDP'])}",
                }
                
                await self._send_event(event)
                scan_count += 1
                
                # Very small delay between port scans
                await asyncio.sleep(random.uniform(0.01, 0.05))
            
            # Check if we should continue
            if (end_time - datetime.utcnow()).total_seconds() <= 0:
                break
        
        print(f"Port scan completed: {scan_count} ports scanned")
    
    async def replay_data_exfiltration(
        self,
        source_ip: str = "192.168.1.50",
        attacker_ip: str = "104.238.161.63",
        duration_minutes: int = 10,
        files_per_minute: int = 5,
    ):
        """Replay data exfiltration attack."""
        print(f"Replaying data exfiltration from {source_ip} to {attacker_ip}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        file_types = [
            ".pdf", ".docx", ".xlsx", ".csv", ".sql", ".db",
            ".zip", ".rar", ".tar.gz", ".log", ".conf"
        ]
        
        file_sizes = [1000000, 5000000, 10000000, 50000000]  # 1MB to 50MB
        
        transfer_count = 0
        total_bytes = 0
        
        while datetime.utcnow() < end_time:
            # Simulate file transfers
            transfers_this_minute = random.randint(
                files_per_minute // 2,
                files_per_minute * 2
            )
            
            for i in range(transfers_this_minute):
                file_size = random.choice(file_sizes)
                file_type = random.choice(file_types)
                filename = f"data_{random.randint(1000, 9999)}{file_type}"
                
                # Simulate HTTP upload
                event = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "http_request",
                    "src_ip": source_ip,
                    "dst_ip": attacker_ip,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": 443,
                    "method": "POST",
                    "path": f"/upload/{filename}",
                    "status_code": 200,
                    "bytes_sent": file_size,
                    "user_agent": "curl/7.68.0",
                    "referrer": "",
                    "hostname": "fileserver-01",
                    "message": f"{source_ip} - - [{datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"POST /upload/{filename} HTTP/1.1\" 200 {file_size}",
                }
                
                await self._send_event(event)
                
                transfer_count += 1
                total_bytes += file_size
                
                # Small delay between transfers
                await asyncio.sleep(random.uniform(1, 3))
            
            # Wait for next minute or until end
            remaining_time = (end_time - datetime.utcnow()).total_seconds()
            if remaining_time > 60:
                await asyncio.sleep(60)
            else:
                await asyncio.sleep(remaining_time)
        
        print(f"Data exfiltration completed: {transfer_count} files, {total_bytes/1024/1024:.1f} MB")
    
    async def replay_malware_execution(
        self,
        infected_host: str = "192.168.1.75",
        c2_server: str = "45.134.26.178",
        duration_minutes: int = 3,
    ):
        """Replay malware execution and C2 communication."""
        print(f"Replaying malware execution on {infected_host}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        # Initial execution
        execution_event = {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": "process_execution",
            "process_name": "malware.exe",
            "process_id": random.randint(1000, 9999),
            "parent_process": "explorer.exe",
            "parent_pid": random.randint(100, 500),
            "user": "SYSTEM",
            "hostname": "workstation-01",
            "command_line": "malware.exe --silent --persist",
            "working_directory": "C:\\Windows\\Temp",
            "integrity_level": "High",
            "message": "Process malware.exe (PID: 1234) started by SYSTEM",
        }
        
        await self._send_event(execution_event)
        print("  Malware executed")
        
        # C2 communication
        c2_count = 0
        
        while datetime.utcnow() < end_time:
            # DNS query for C2 domain
            dns_event = {
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "dns_query",
                "src_ip": infected_host,
                "query": f"c2-{random.randint(100, 999)}.malicious-domain.com",
                "query_type": "A",
                "response": c2_server,
                "response_code": 0,
                "response_time_ms": random.randint(10, 100),
                "dns_server": "8.8.8.8",
                "hostname": "workstation-01",
                "message": f"DNS query: c2-{random.randint(100, 999)}.malicious-domain.com (A) from {infected_host}",
            }
            
            await self._send_event(dns_event)
            c2_count += 1
            
            # HTTP beacon
            beacon_event = {
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "http_request",
                "src_ip": infected_host,
                "dst_ip": c2_server,
                "src_port": random.randint(1024, 65535),
                "dst_port": 443,
                "method": "GET",
                "path": f"/beacon/{random.randint(1000, 9999)}",
                "status_code": 200,
                "bytes_sent": random.randint(100, 1000),
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "referrer": "",
                "hostname": "workstation-01",
                "message": f"{infected_host} - - [{datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"GET /beacon/{random.randint(1000, 9999)} HTTP/1.1\" 200 {random.randint(100, 1000)}",
            }
            
            await self._send_event(beacon_event)
            
            # Wait between beacons
            await asyncio.sleep(random.uniform(30, 120))
        
        print(f"Malware execution completed: {c2_count} C2 communications")
    
    async def replay_web_attack(
        self,
        target_web: str = "192.168.1.20",
        attacker_ip: str = "203.0.113.45",
        duration_minutes: int = 5,
        requests_per_minute: int = 30,
    ):
        """Replay web application attacks."""
        print(f"Replaying web attacks from {attacker_ip} to {target_web}")
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        
        attack_patterns = [
            ("/admin.php", "GET", 404),
            ("/wp-login.php", "POST", 200),
            ("/api/users", "GET", 403),
            ("/shell.php", "GET", 404),
            ("/../../../etc/passwd", "GET", 403),
            ("/search?q=<script>alert(1)</script>", "GET", 200),
            ("/login", "POST", 200),
            ("/upload.php", "POST", 413),
        ]
        
        attack_count = 0
        
        while datetime.utcnow() < end_time:
            # Generate attacks for this minute
            attacks_this_minute = random.randint(
                requests_per_minute // 2,
                requests_per_minute * 2
            )
            
            for i in range(attacks_this_minute):
                path, method, status = random.choice(attack_patterns)
                
                event = {
                    "@timestamp": datetime.utcnow().isoformat() + "Z",
                    "event_type": "http_request",
                    "src_ip": attacker_ip,
                    "dst_ip": target_web,
                    "src_port": random.randint(1024, 65535),
                    "dst_port": 80,
                    "method": method,
                    "path": path,
                    "status_code": status,
                    "bytes_sent": random.randint(100, 5000),
                    "user_agent": random.choice([
                        "sqlmap/1.4.8",
                        "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
                        "nikto/2.1.6",
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    ]),
                    "referrer": "",
                    "hostname": "webserver-01",
                    "message": f"{attacker_ip} - - [{datetime.utcnow().strftime('%d/%b/%Y:%H:%M:%S')} +0000] \"{method} {path} HTTP/1.1\" {status} {random.randint(100, 5000)}",
                }
                
                await self._send_event(event)
                attack_count += 1
                
                # Small delay between requests
                await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Wait for next minute
            remaining_time = (end_time - datetime.utcnow()).total_seconds()
            if remaining_time > 60:
                await asyncio.sleep(60)
            else:
                await asyncio.sleep(remaining_time)
        
        print(f"Web attacks completed: {attack_count} malicious requests")
    
    async def _send_event(self, event: Dict[str, Any]):
        """Send event to SOC platform API."""
        try:
            # In a real implementation, this would send to the ingestion API
            # For now, we'll just print or save to file
            print(f"  Event: {event['event_type']} from {event.get('src_ip', 'unknown')}")
            
            # Simulate API call
            # response = requests.post(
            #     f"{self.api_url}/api/v1/events",
            #     json=event,
            #     timeout=5
            # )
            # return response.status_code == 200
            
            # Save to file for testing
            with open("data/raw/replay_events.jsonl", "a") as f:
                f.write(json.dumps(event) + "\n")
            
            return True
            
        except Exception as e:
            print(f"Error sending event: {e}")
            return False


async def main():
    parser = argparse.ArgumentParser(description="Replay attack scenarios for SOC platform testing")
    parser.add_argument(
        "--scenario",
        choices=["all", "brute_force", "port_scan", "data_exfil", "malware", "web_attack"],
        default="all",
        help="Attack scenario to replay"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Duration in minutes for each attack"
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8080",
        help="SOC platform API URL"
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run scenarios in parallel"
    )
    
    args = parser.parse_args()
    
    replayer = AttackReplayer(api_url=args.api_url)
    
    # Clear output file
    open("data/raw/replay_events.jsonl", "w").close()
    
    scenarios_to_run = []
    
    if args.scenario == "all" or args.scenario == "brute_force":
        scenarios_to_run.append(
            replayer.replay_brute_force(duration_minutes=args.duration)
        )
    
    if args.scenario == "all" or args.scenario == "port_scan":
        scenarios_to_run.append(
            replayer.replay_port_scan(duration_minutes=args.duration)
        )
    
    if args.scenario == "all" or args.scenario == "data_exfil":
        scenarios_to_run.append(
            replayer.replay_data_exfiltration(duration_minutes=args.duration)
        )
    
    if args.scenario == "all" or args.scenario == "malware":
        scenarios_to_run.append(
            replayer.replay_malware_execution(duration_minutes=args.duration)
        )
    
    if args.scenario == "all" or args.scenario == "web_attack":
        scenarios_to_run.append(
            replayer.replay_web_attack(duration_minutes=args.duration)
        )
    
    print(f"Starting {len(scenarios_to_run)} attack scenarios...")
    
    if args.parallel and len(scenarios_to_run) > 1:
        # Run all scenarios in parallel
        await asyncio.gather(*scenarios_to_run)
    else:
        # Run scenarios sequentially
        for scenario in scenarios_to_run:
            await scenario
    
    print("\nAll attack scenarios completed!")
    print(f"Events saved to: data/raw/replay_events.jsonl")


if __name__ == "__main__":
    asyncio.run(main())