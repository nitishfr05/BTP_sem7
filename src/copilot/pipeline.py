"""Network Security Copilot inference pipeline supporting API models and modular defences."""

import os
import time
from typing import Dict, Any, Optional, List, Callable
from dotenv import load_dotenv

from src.copilot.log_parsers import NetworkLogRecord
from src.copilot.prompt_templates import (
    CLASSIFICATION_SYSTEM_PROMPT,
    CLASSIFICATION_USER_PROMPT,
    SUMMARIZATION_SYSTEM_PROMPT,
    SUMMARIZATION_USER_PROMPT,
    parse_copilot_classification_response,
    parse_copilot_summarization_response,
)

# Load environment variables
load_dotenv()


class NetworkCopilot:
    """LLM-based network security monitoring copilot with pluggable defences."""

    def __init__(
        self,
        model_name: str = "openai/gpt-oss-20b",
        provider: str = "groq",
        api_key: Optional[str] = None,
        temperature: float = 0.0,
        defences: Optional[List[str]] = None,
        delay_seconds: float = 0.5,
    ):
        """
        Initialize copilot pipeline.
        
        Args:
            model_name: Model identifier (e.g. 'llama-3.1-8b-instant', 'mixtral-8x7b-32768', 'gemma2-9b-it')
            provider: 'groq' or 'together'
            api_key: API key or read from environment
            temperature: LLM temperature (0.0 for deterministic benchmark)
            defences: List of active defences: 'boundary_awareness', 'spotlighting', 'classifier_filter'
            delay_seconds: Delay between requests to respect rate limits
        """
        self.model_name = model_name
        self.provider = provider
        self.temperature = temperature
        self.defences = defences or []
        self.delay_seconds = delay_seconds

        # Resolve API key
        if provider == "groq":
            self.api_key = api_key or os.getenv("GROQ_API_KEY")
            if not self.api_key or self.api_key.startswith("gsk_your_groq"):
                self.client = None
            else:
                from groq import Groq
                self.client = Groq(api_key=self.api_key)
        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def is_configured(self) -> bool:
        """Check if API client is initialized with a valid key."""
        return self.client is not None

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Execute chat completion call to API with retry logic."""
        if not self.is_configured():
            raise RuntimeError(
                "Groq API key not set. Please provide a valid GROQ_API_KEY in .env or constructor."
            )

        max_retries = 5
        base_delay = 2.0

        for attempt in range(max_retries):
            try:
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=self.temperature,
                    response_format={"type": "json_object"} if "llama-3" in self.model_name or "mixtral" in self.model_name else None,
                )
                if self.delay_seconds > 0:
                    time.sleep(self.delay_seconds)
                return response.choices[0].message.content or ""
            except Exception as e:
                err_str = str(e).lower()
                if "rate_limit" in err_str or "429" in err_str:
                    wait_time = base_delay * (2 ** attempt)
                    time.sleep(wait_time)
                elif attempt == max_retries - 1:
                    raise
                else:
                    time.sleep(base_delay)
        return ""

    def classify_log(
        self,
        log_input: Any,  # NetworkLogRecord or formatted string
        custom_system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classify a single network telemetry record.
        
        Returns dict containing:
            classification, confidence, explanation, indicators, latency_ms,
            filter_triggered, defence_overhead_ms
        """
        start_time = time.perf_counter()

        # Format input string
        if isinstance(log_input, NetworkLogRecord):
            raw_text = log_input.to_copilot_string()
        else:
            raw_text = str(log_input)

        processed_text = raw_text
        system_prompt = custom_system_prompt or CLASSIFICATION_SYSTEM_PROMPT
        filter_triggered = False

        # Apply Defence 3: Classifier / Heuristic Pre-filter
        if "classifier_filter" in self.defences:
            from src.defences.classifier_filter import check_injection_filter
            is_malicious_payload, pattern = check_injection_filter(raw_text)
            if is_malicious_payload:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "classification": "malicious",
                    "confidence": 1.0,
                    "explanation": f"Security Pre-Filter blocked input: suspected prompt injection payload ({pattern})",
                    "indicators": ["adversarial_payload_detected"],
                    "latency_ms": elapsed_ms,
                    "filter_triggered": True,
                    "defence_overhead_ms": elapsed_ms,
                    "raw_response": ""
                }

        # Apply Defence 1: Boundary-Awareness Prompting
        if "boundary_awareness" in self.defences:
            from src.defences.boundary_awareness import apply_boundary_awareness_prompt
            system_prompt = apply_boundary_awareness_prompt(system_prompt)

        # Apply Defence 2: Spotlighting / Data Marking
        if "spotlighting" in self.defences:
            from src.defences.spotlighting import spotlight_data_mark
            processed_text = spotlight_data_mark(processed_text)

        user_prompt = CLASSIFICATION_USER_PROMPT.format(log_entry=processed_text)

        # Execute LLM call
        raw_output = self._call_llm(system_prompt, user_prompt)
        parsed = parse_copilot_classification_response(raw_output)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        parsed["latency_ms"] = elapsed_ms
        parsed["filter_triggered"] = filter_triggered
        parsed["raw_response"] = raw_output
        return parsed

    def summarize_logs(
        self,
        logs: List[Any],
        custom_system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Summarize a batch of network telemetry records.
        """
        start_time = time.perf_counter()

        formatted_logs = []
        for i, entry in enumerate(logs, 1):
            if isinstance(entry, NetworkLogRecord):
                entry_str = entry.to_copilot_string()
            else:
                entry_str = str(entry)
            formatted_logs.append(f"[Record {i}]\n{entry_str}")

        combined_text = "\n\n".join(formatted_logs)
        system_prompt = custom_system_prompt or SUMMARIZATION_SYSTEM_PROMPT

        # Apply Defences
        if "classifier_filter" in self.defences:
            from src.defences.classifier_filter import check_injection_filter
            is_malicious, pattern = check_injection_filter(combined_text)
            if is_malicious:
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                return {
                    "threat_level": "critical",
                    "incident_summary": f"Attack payload detected in log stream: {pattern}. Automated alert raised.",
                    "malicious_detected": True,
                    "recommended_action": "Block source IP immediately and isolate telemetry channel.",
                    "latency_ms": elapsed_ms,
                    "filter_triggered": True
                }

        if "boundary_awareness" in self.defences:
            from src.defences.boundary_awareness import apply_boundary_awareness_prompt
            system_prompt = apply_boundary_awareness_prompt(system_prompt)

        if "spotlighting" in self.defences:
            from src.defences.spotlighting import spotlight_data_mark
            combined_text = spotlight_data_mark(combined_text)

        user_prompt = SUMMARIZATION_USER_PROMPT.format(log_entries=combined_text)
        raw_output = self._call_llm(system_prompt, user_prompt)
        parsed = parse_copilot_summarization_response(raw_output)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        parsed["latency_ms"] = elapsed_ms
        parsed["filter_triggered"] = False
        parsed["raw_response"] = raw_output
        return parsed
