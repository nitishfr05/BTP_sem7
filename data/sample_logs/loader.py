"""Utility loader to parse sample dataset and partition into benign and malicious records."""

import os
from typing import List, Tuple
from src.copilot.log_parsers import parse_zeek_log, parse_suricata_eve, NetworkLogRecord


def load_sample_dataset(data_dir: str = "data/sample_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """
    Load sample Zeek and Suricata logs and return (benign_records, malicious_records).
    """
    benign: List[NetworkLogRecord] = []
    malicious: List[NetworkLogRecord] = []

    conn_path = os.path.join(data_dir, "sample_zeek_conn.json")
    http_path = os.path.join(data_dir, "sample_zeek_http.json")
    dns_path = os.path.join(data_dir, "sample_zeek_dns.json")
    eve_path = os.path.join(data_dir, "sample_suricata_eve.json")

    # Zeek conn
    if os.path.exists(conn_path):
        for rec in parse_zeek_log(conn_path, "conn"):
            if "185.220.101" in rec.source_ip or rec.dest_port in [81, 82]:
                rec.ground_truth = "malicious"
                malicious.append(rec)
            else:
                rec.ground_truth = "benign"
                benign.append(rec)

    # Zeek HTTP
    if os.path.exists(http_path):
        for rec in parse_zeek_log(http_path, "http"):
            if "sqlmap" in str(rec.raw_fields.get("user_agent", "")) or "Nikto" in str(rec.raw_fields.get("user_agent", "")):
                rec.ground_truth = "malicious"
                malicious.append(rec)
            else:
                rec.ground_truth = "benign"
                benign.append(rec)

    # Zeek DNS
    if os.path.exists(dns_path):
        for rec in parse_zeek_log(dns_path, "dns"):
            if "c2-" in rec.summary_text or "badactor" in rec.summary_text:
                rec.ground_truth = "malicious"
                malicious.append(rec)
            else:
                rec.ground_truth = "benign"
                benign.append(rec)

    # Suricata EVE
    if os.path.exists(eve_path):
        for rec in parse_suricata_eve(eve_path):
            severity = rec.raw_fields.get("severity", 3)
            if severity <= 2:
                rec.ground_truth = "malicious"
                malicious.append(rec)
            else:
                rec.ground_truth = "benign"
                benign.append(rec)

    return benign, malicious
