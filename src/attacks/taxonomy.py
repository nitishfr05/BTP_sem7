"""Taxonomy of prompt injection attacks adapted for network telemetry channels."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any


class AttackCategory(str, Enum):
    """Four core attack payload categories."""
    DIRECT_OVERRIDE = "direct_override"
    PERSONA_HIJACK = "persona_hijack"
    CONTEXT_MANIPULATION = "context_manipulation"
    ENCODING_OBFUSCATION = "encoding_obfuscation"


class TelemetryChannel(str, Enum):
    """Network telemetry channels where adversarial payloads can reside."""
    RAW_LOG = "raw_log"
    USER_AGENT = "user_agent"
    DNS_QUERY = "dns_query"
    ALERT_MSG = "alert_msg"
    ALERT_DESC = "alert_desc"


@dataclass
class AttackPayload:
    """Representation of an adversarial prompt injection payload."""
    payload_id: str
    category: AttackCategory
    channel_compatibility: list[TelemetryChannel]
    template_text: str
    target_intent: str  # 'force_benign', 'suppress_alert', 'leak_prompt'
    description: str
    obfuscation_type: Optional[str] = None  # e.g., 'base64', 'hex', 'rot13', 'url_encode'

    def format_for_channel(self, channel: TelemetryChannel) -> str:
        """Format the payload to respect syntactical field constraints of the channel."""
        text = self.template_text.strip()

        if channel == TelemetryChannel.DNS_QUERY:
            # DNS labels max 63 chars, whole name max 253 chars, alphanumeric + hyphens
            # Use subdomain or formatted label representation
            safe_text = "".join(c if c.isalnum() else "-" for c in text.lower())[:60]
            return f"{safe_text}.injection-test.corp.internal"

        elif channel == TelemetryChannel.USER_AGENT:
            # Look like a User-Agent containing injected instructions
            return f"Mozilla/5.0 (SecurityScan; {text}) Gecko/20100101 Firefox/125.0"

        elif channel == TelemetryChannel.ALERT_MSG:
            # Look like an IDS signature
            return f"ET POLICY Inbound Inspection: {text}"

        elif channel == TelemetryChannel.ALERT_DESC:
            # Free-form alert note
            return f"Analyst Review Required. Note: {text}"

        else:  # RAW_LOG
            return f" -- note: {text}"
