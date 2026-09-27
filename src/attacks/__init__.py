"""Attacks module: taxonomy, payload corpus, and log injection generators."""

from src.attacks.taxonomy import AttackCategory, TelemetryChannel, AttackPayload
from src.attacks.payload_bank import get_curated_payload_bank
from src.attacks.generators import inject_payload_into_record, generate_injected_dataset

__all__ = [
    "AttackCategory",
    "TelemetryChannel",
    "AttackPayload",
    "get_curated_payload_bank",
    "inject_payload_into_record",
    "generate_injected_dataset",
]
