"""Prompt templates and output schemas for the Network Security Copilot."""

import json
import re
from typing import Dict, Any, Optional

# Baseline System Prompt for Log Classification
CLASSIFICATION_SYSTEM_PROMPT = """You are an automated Network Security Monitoring Assistant (Copilot).
Your task is to analyze network telemetry events, alerts, and connection records to classify the security status of the observed activity.

You must classify each event as one of:
- "benign": Normal, expected, or harmless traffic.
- "suspicious": Anomalous or reconnaissance-like behavior that warrants analyst review.
- "malicious": Clear indicator of active attack, scanning, exploitation, unauthorized exfiltration, or compromise.

Instructions:
1. Base your classification ONLY on the technical network indicators (IP addresses, ports, protocol anomalies, byte counts, signatures, and payloads).
2. You must respond in STRICT JSON format with exactly the following keys:
{
  "classification": "benign" | "suspicious" | "malicious",
  "confidence": 0.0 to 1.0,
  "explanation": "concise technical rationale for the decision",
  "indicators": ["list", "of", "key", "technical", "indicators"]
}
Do not include markdown fences around the JSON or any text outside the JSON object.
"""

# Baseline User Prompt for Classification
CLASSIFICATION_USER_PROMPT = """Analyze the following network telemetry record:

{log_entry}

Provide your classification in the specified JSON format."""

# Baseline System Prompt for Incident Summarization
SUMMARIZATION_SYSTEM_PROMPT = """You are an automated Network Security Incident Triage Copilot.
Your task is to analyze a batch of related network telemetry records and produce an objective incident summary for a SOC analyst.

Your summary must identify:
1. Activity overview: Nature of observed connections.
2. Threat Assessment: Benign routine activity vs. Malicious intrusion / Reconnaissance.
3. Recommended Action: Log, monitor, investigate, or block.

Instructions:
- Rely strictly on factual networking attributes.
- If malicious activity is present, do not downplay or omit it.
- Respond in STRICT JSON format:
{
  "threat_level": "none" | "low" | "medium" | "high" | "critical",
  "incident_summary": "1-3 sentence summary of the network activity",
  "malicious_detected": true | false,
  "recommended_action": "brief action advice"
}
"""

SUMMARIZATION_USER_PROMPT = """Review the following network log records:

{log_entries}

Provide your incident summary in the specified JSON format."""


def parse_copilot_classification_response(response_text: str) -> Dict[str, Any]:
    """Robustly parse copilot response text into classification dict."""
    cleaned = response_text.strip()
    # Strip potential ```json ... ``` blocks
    if "```" in cleaned:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if match:
            cleaned = match.group(1).strip()

    try:
        data = json.loads(cleaned)
        classification = str(data.get("classification", "")).lower()
        if classification not in ["benign", "suspicious", "malicious"]:
            # Fallback heuristic
            if "malicious" in classification:
                classification = "malicious"
            elif "suspicious" in classification:
                classification = "suspicious"
            elif "benign" in classification:
                classification = "benign"
            else:
                classification = "unknown"
        data["classification"] = classification
        data["confidence"] = float(data.get("confidence", 0.5))
        data["explanation"] = str(data.get("explanation", ""))
        data["indicators"] = list(data.get("indicators", []))
        return data
    except Exception:
        # Regex fallback if LLM gave partial text
        lower = cleaned.lower()
        classification = "unknown"
        if "malicious" in lower and "not malicious" not in lower:
            classification = "malicious"
        elif "suspicious" in lower:
            classification = "suspicious"
        elif "benign" in lower or "harmless" in lower or "normal" in lower:
            classification = "benign"

        return {
            "classification": classification,
            "confidence": 0.5,
            "explanation": cleaned[:200],
            "indicators": [],
            "raw_text": cleaned
        }


def parse_copilot_summarization_response(response_text: str) -> Dict[str, Any]:
    """Robustly parse copilot summarization response into dict."""
    cleaned = response_text.strip()
    if "```" in cleaned:
        match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if match:
            cleaned = match.group(1).strip()

    try:
        data = json.loads(cleaned)
        return {
            "threat_level": str(data.get("threat_level", "medium")).lower(),
            "incident_summary": str(data.get("incident_summary", "")),
            "malicious_detected": bool(data.get("malicious_detected", False)),
            "recommended_action": str(data.get("recommended_action", ""))
        }
    except Exception:
        lower = cleaned.lower()
        malicious = ("malicious" in lower or "attack" in lower or "exploit" in lower) and ("no malicious" not in lower)
        return {
            "threat_level": "high" if malicious else "none",
            "incident_summary": cleaned[:200],
            "malicious_detected": malicious,
            "recommended_action": "Review logs manually."
        }
