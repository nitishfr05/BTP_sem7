"""Generators to embed attack payloads into network telemetry fields."""

import copy
import json
from typing import List, Dict, Any, Optional
from src.copilot.log_parsers import NetworkLogRecord
from src.attacks.taxonomy import TelemetryChannel, AttackPayload


def inject_payload_into_record(
    clean_record: NetworkLogRecord,
    payload: AttackPayload,
    channel: TelemetryChannel
) -> NetworkLogRecord:
    """
    Embed an attack payload into a specific telemetry channel of a clean log record.
    
    Returns a new NetworkLogRecord with the payload injected and metadata recorded.
    """
    injected_record = copy.deepcopy(clean_record)
    injected_str = payload.format_for_channel(channel)

    injected_record.record_id = f"{clean_record.record_id}-inj-{payload.payload_id}-{channel.value}"
    injected_record.raw_fields["injection_metadata"] = {
        "payload_id": payload.payload_id,
        "category": payload.category.value,
        "channel": channel.value,
        "target_intent": payload.target_intent,
        "raw_payload_text": payload.template_text,
        "formatted_payload": injected_str
    }

    if channel == TelemetryChannel.RAW_LOG:
        injected_record.summary_text = f"{injected_record.summary_text} {injected_str}"
        injected_record.raw_fields["raw_injected"] = injected_str

    elif channel == TelemetryChannel.USER_AGENT:
        injected_record.raw_fields["user_agent"] = injected_str
        injected_record.summary_text = f"{injected_record.summary_text} (User-Agent: {injected_str})"

    elif channel == TelemetryChannel.DNS_QUERY:
        injected_record.raw_fields["query"] = injected_str
        injected_record.summary_text = f"DNS Query: {injected_str}; Answers=[]"

    elif channel == TelemetryChannel.ALERT_MSG:
        injected_record.raw_fields["alert_msg"] = injected_str
        injected_record.summary_text = f"ALERT: {injected_str} [Severity: 1]"

    elif channel == TelemetryChannel.ALERT_DESC:
        injected_record.raw_fields["alert_desc"] = injected_str
        injected_record.summary_text = f"{injected_record.summary_text}; Note: {injected_str}"

    return injected_record


def generate_injected_dataset(
    clean_records: List[NetworkLogRecord],
    payload_bank: List[AttackPayload],
    channels: Optional[List[TelemetryChannel]] = None
) -> List[NetworkLogRecord]:
    """
    Generate the cross-product dataset of (malicious logs x payloads x compatible channels).
    """
    channels = channels or list(TelemetryChannel)
    injected_dataset = []

    for record in clean_records:
        for payload in payload_bank:
            for ch in channels:
                if ch in payload.channel_compatibility:
                    inj_rec = inject_payload_into_record(record, payload, ch)
                    injected_dataset.append(inj_rec)

    return injected_dataset
