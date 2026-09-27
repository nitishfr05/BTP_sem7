"""Parsers for Zeek and Suricata telemetry logs into unified structured representation."""

import json
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class NetworkLogRecord:
    """Unified representation of a network log entry across sensors."""
    record_id: str
    sensor: str  # 'zeek' or 'suricata'
    log_type: str  # e.g., 'conn', 'http', 'dns', 'alert'
    source_ip: str
    source_port: Optional[int]
    dest_ip: str
    dest_port: Optional[int]
    proto: str
    timestamp: str
    summary_text: str
    raw_fields: Dict[str, Any] = field(default_factory=dict)
    ground_truth: str = "benign"  # 'benign' or 'malicious'

    def to_copilot_string(self) -> str:
        """Format log record as clean text presentation for the LLM copilot."""
        lines = [
            f"Sensor: {self.sensor.upper()} [{self.log_type}]",
            f"Timestamp: {self.timestamp}",
            f"Flow: {self.source_ip}:{self.source_port} -> {self.dest_ip}:{self.dest_port} ({self.proto.upper()})",
            f"Details: {self.summary_text}"
        ]
        # Include specific contextual fields if available
        if "user_agent" in self.raw_fields:
            lines.append(f"HTTP User-Agent: {self.raw_fields['user_agent']}")
        if "query" in self.raw_fields:
            lines.append(f"DNS Query: {self.raw_fields['query']}")
        if "alert_msg" in self.raw_fields:
            lines.append(f"Alert Message: {self.raw_fields['alert_msg']}")
        if "severity" in self.raw_fields:
            lines.append(f"Reported Severity: {self.raw_fields['severity']}")
        return "\n".join(lines)


def parse_zeek_json_line(line: str, log_type: str = "conn", record_id: str = "") -> Optional[NetworkLogRecord]:
    """Parse a single JSON-formatted line from Zeek."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        data = json.loads(line)
        src_ip = data.get("id.orig_h") or data.get("src_ip", "0.0.0.0")
        src_port = data.get("id.orig_p") or data.get("src_port")
        dst_ip = data.get("id.resp_h") or data.get("dst_ip", "0.0.0.0")
        dst_port = data.get("id.resp_p") or data.get("dst_port")
        proto = data.get("proto", "tcp")
        ts = str(data.get("ts", ""))

        summary_parts = []
        raw_fields = dict(data)

        if log_type == "conn":
            history = data.get("history", "")
            orig_bytes = data.get("orig_bytes", 0)
            resp_bytes = data.get("resp_bytes", 0)
            conn_state = data.get("conn_state", "")
            summary_parts.append(f"State={conn_state}, History={history}, Sent={orig_bytes}B, Recv={resp_bytes}B")
        elif log_type == "http":
            method = data.get("method", "GET")
            host = data.get("host", "")
            uri = data.get("uri", "/")
            ua = data.get("user_agent", "")
            summary_parts.append(f"{method} http://{host}{uri}")
            raw_fields["user_agent"] = ua
        elif log_type == "dns":
            query = data.get("query", "")
            qtype = data.get("qtype_name", "A")
            answers = data.get("answers", [])
            summary_parts.append(f"Query {query} ({qtype}), Answers={answers}")
            raw_fields["query"] = query
        else:
            summary_parts.append(f"Generic event: {list(data.keys())[:5]}")

        return NetworkLogRecord(
            record_id=record_id or f"zeek-{ts}",
            sensor="zeek",
            log_type=log_type,
            source_ip=str(src_ip),
            source_port=int(src_port) if src_port is not None else None,
            dest_ip=str(dst_ip),
            dest_port=int(dst_port) if dst_port is not None else None,
            proto=str(proto),
            timestamp=ts,
            summary_text="; ".join(summary_parts),
            raw_fields=raw_fields
        )
    except Exception:
        return None


def parse_suricata_eve_line(line: str, record_id: str = "") -> Optional[NetworkLogRecord]:
    """Parse a single line of Suricata EVE JSON."""
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        event_type = data.get("event_type", "alert")
        src_ip = data.get("src_ip", "0.0.0.0")
        src_port = data.get("src_port")
        dst_ip = data.get("dest_ip", "0.0.0.0")
        dst_port = data.get("dest_port")
        proto = data.get("proto", "tcp")
        ts = data.get("timestamp", "")

        raw_fields = dict(data)
        summary_parts = []

        if event_type == "alert":
            alert_info = data.get("alert", {})
            msg = alert_info.get("signature", "Unknown Signature")
            severity = alert_info.get("severity", 3)
            category = alert_info.get("category", "Generic")
            summary_parts.append(f"ALERT: {msg} [Cat: {category}, Severity: {severity}]")
            raw_fields["alert_msg"] = msg
            raw_fields["severity"] = severity
        elif event_type == "http":
            http = data.get("http", {})
            hostname = http.get("hostname", "")
            url = http.get("url", "/")
            ua = http.get("http_user_agent", "")
            summary_parts.append(f"HTTP {http.get('http_method', 'GET')} {hostname}{url}")
            raw_fields["user_agent"] = ua
        elif event_type == "dns":
            dns = data.get("dns", {})
            qname = dns.get("rrname", "")
            summary_parts.append(f"DNS {dns.get('type', 'query')} for {qname}")
            raw_fields["query"] = qname
        else:
            summary_parts.append(f"Event: {event_type}")

        return NetworkLogRecord(
            record_id=record_id or f"suri-{ts}",
            sensor="suricata",
            log_type=event_type,
            source_ip=str(src_ip),
            source_port=int(src_port) if src_port is not None else None,
            dest_ip=str(dst_ip),
            dest_port=int(dst_port) if dst_port is not None else None,
            proto=str(proto),
            timestamp=ts,
            summary_text="; ".join(summary_parts),
            raw_fields=raw_fields
        )
    except Exception:
        return None


def parse_zeek_log(filepath: str, log_type: str = "conn") -> List[NetworkLogRecord]:
    """Parse an entire Zeek JSON log file into records."""
    records = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            rec = parse_zeek_json_line(line, log_type=log_type, record_id=f"zeek-{log_type}-{i}")
            if rec:
                records.append(rec)
    return records


def parse_suricata_eve(filepath: str) -> List[NetworkLogRecord]:
    """Parse an entire Suricata eve.json file into records."""
    records = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            rec = parse_suricata_eve_line(line, record_id=f"eve-{i}")
            if rec:
                records.append(rec)
    return records
