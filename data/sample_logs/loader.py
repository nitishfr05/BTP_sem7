"""Utility loader to parse datasets (sample, expanded, or live testbed logs) and partition into benign and malicious records."""

import os
import glob
from typing import List, Tuple
from src.copilot.log_parsers import parse_zeek_log, parse_suricata_eve, NetworkLogRecord


def load_dataset(data_dir: str = "data/expanded_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """
    Load Zeek and Suricata logs from data_dir and return (benign_records, malicious_records).
    Supports:
      - 'data/sample_logs'
      - 'data/expanded_logs'
      - 'data/raw_logs' or 'testbed' (auto-resolves btp_final_testbed_logs)
    """
    if data_dir in ["testbed", "live", "raw"]:
        # Find directory containing testbed logs
        candidate = "data/raw_logs/btp_final_testbed_logs/final_testbed_logs"
        if os.path.exists(candidate):
            data_dir = candidate
        else:
            data_dir = "data/raw_logs"

    if not os.path.exists(data_dir):
        # Fallback to expanded_logs or sample_logs
        data_dir = "data/expanded_logs" if os.path.exists("data/expanded_logs") else "data/sample_logs"

    benign: List[NetworkLogRecord] = []
    malicious: List[NetworkLogRecord] = []

    # Find matching files in directory
    for f in os.listdir(data_dir):
        full_path = os.path.join(data_dir, f)
        if not (f.endswith(".json") or f.endswith(".log")):
            continue

        if "conn" in f:
            for rec in parse_zeek_log(full_path, "conn"):
                gt = rec.raw_fields.get("_ground_truth")
                if gt:
                    rec.ground_truth = gt
                elif "185.220.101" in rec.source_ip or rec.dest_port in [81, 82]:
                    rec.ground_truth = "malicious"
                elif rec.dest_port in [80, 8080, 21, 22, 23, 25, 443, 3306] and rec.raw_fields.get("conn_state") in ["RSTRH", "S0", "REJ"]:
                    rec.ground_truth = "malicious"
                else:
                    rec.ground_truth = "benign"

                if rec.ground_truth == "malicious":
                    malicious.append(rec)
                else:
                    benign.append(rec)

        elif "http" in f:
            for rec in parse_zeek_log(full_path, "http"):
                gt = rec.raw_fields.get("_ground_truth")
                if gt:
                    rec.ground_truth = gt
                elif "sqlmap" in str(rec.raw_fields.get("user_agent", "")) or "Nikto" in str(rec.raw_fields.get("user_agent", "")):
                    rec.ground_truth = "malicious"
                else:
                    rec.ground_truth = "benign"

                if rec.ground_truth == "malicious":
                    malicious.append(rec)
                else:
                    benign.append(rec)

        elif "dns" in f:
            for rec in parse_zeek_log(full_path, "dns"):
                gt = rec.raw_fields.get("_ground_truth")
                if gt:
                    rec.ground_truth = gt
                elif any(k in rec.summary_text.lower() for k in ["c2-", "badactor", "dga", "exfil"]):
                    rec.ground_truth = "malicious"
                else:
                    rec.ground_truth = "benign"

                if rec.ground_truth == "malicious":
                    malicious.append(rec)
                else:
                    benign.append(rec)

        elif "eve" in f or "suricata" in f:
            for rec in parse_suricata_eve(full_path):
                gt = rec.raw_fields.get("_ground_truth")
                if gt:
                    rec.ground_truth = gt
                else:
                    severity = rec.raw_fields.get("severity", 3)
                    if rec.log_type == "alert" and severity <= 2:
                        rec.ground_truth = "malicious"
                    elif any(k in rec.summary_text.lower() for k in ["sql", "attack", "exploit", "trojan"]):
                        rec.ground_truth = "malicious"
                    else:
                        rec.ground_truth = "benign"

                if rec.ground_truth == "malicious":
                    malicious.append(rec)
                else:
                    benign.append(rec)

    return benign, malicious


def load_sample_dataset(data_dir: str = "data/sample_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """Backward compatibility wrapper for sample logs."""
    return load_dataset(data_dir=data_dir)
