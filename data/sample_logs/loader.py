"""Utility loader to parse datasets (sample or expanded) and partition into benign and malicious records."""

import os
import glob
from typing import List, Tuple
from src.copilot.log_parsers import parse_zeek_log, parse_suricata_eve, NetworkLogRecord


def load_dataset(data_dir: str = "data/expanded_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """
    Load Zeek and Suricata logs from data_dir and return (benign_records, malicious_records).
    Supports both sample_logs and expanded_logs.
    """
    if not os.path.exists(data_dir):
        # Fallback to sample_logs if expanded_logs doesn't exist
        data_dir = "data/sample_logs"

    benign: List[NetworkLogRecord] = []
    malicious: List[NetworkLogRecord] = []

    # Find matching files in directory
    for f in os.listdir(data_dir):
        full_path = os.path.join(data_dir, f)
        if not f.endswith(".json"):
            continue

        if "conn" in f:
            for rec in parse_zeek_log(full_path, "conn"):
                gt = rec.raw_fields.get("_ground_truth")
                if gt:
                    rec.ground_truth = gt
                elif "185.220.101" in rec.source_ip or rec.dest_port in [81, 82]:
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
                elif "c2-" in rec.summary_text or "badactor" in rec.summary_text or "dga" in rec.summary_text or "exfil" in rec.summary_text:
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
                    rec.ground_truth = "malicious" if severity <= 2 else "benign"

                if rec.ground_truth == "malicious":
                    malicious.append(rec)
                else:
                    benign.append(rec)

    return benign, malicious


def load_sample_dataset(data_dir: str = "data/sample_logs") -> Tuple[List[NetworkLogRecord], List[NetworkLogRecord]]:
    """Backward compatibility wrapper for sample logs."""
    return load_dataset(data_dir=data_dir)
