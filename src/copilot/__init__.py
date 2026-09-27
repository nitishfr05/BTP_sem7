"""Copilot module: parsing, prompt construction, and LLM inference pipeline."""

from src.copilot.log_parsers import parse_zeek_log, parse_suricata_eve, NetworkLogRecord
from src.copilot.pipeline import NetworkCopilot

__all__ = ["parse_zeek_log", "parse_suricata_eve", "NetworkLogRecord", "NetworkCopilot"]
