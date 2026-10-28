"""Names for the MITRE ATT&CK techniques referenced by the bundled rules."""

TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1059": "Command and Scripting Interpreter",
    "T1071": "Application Layer Protocol",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136": "Create Account",
    "T1098": "Account Manipulation",
    "T1003": "OS Credential Dumping",
    "T1190": "Exploit Public-Facing Application",
    "T1204": "User Execution",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1595": "Active Scanning",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo",
}


def describe(ids):
    return [{"id": t, "name": TECHNIQUES.get(t, ""), "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
            for t in ids or []]
