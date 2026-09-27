"""Defence 3: Lightweight Classifier and Heuristic-Based Pre-filter.

Rapidly inspects raw telemetry records for prompt injection signatures,
intent overrides, and instruction-syntax leakage before invoking the LLM.
"""

import re
from typing import Tuple, List, Optional

# Core regular expressions representing prompt injection and goal-hijacking patterns
INJECTION_SIGNATURES: List[Tuple[str, str]] = [
    # Direct instruction overrides
    (r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)", "direct_override_ignore"),
    (r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|guidelines?)", "direct_override_disregard"),
    (r"(?i)forget\s+(all\s+)?(previous|prior|above)\s+instructions?", "direct_override_forget"),
    (r"(?i)new\s+instructions?:", "direct_override_new_inst"),
    (r"(?i)do\s+not\s+follow\s+any\s+prior", "direct_override_do_not_follow"),

    # Persona / Role hijack
    (r"(?i)you\s+are\s+now\s+(a|an)?\s*(helpful|assistant|analyst|security\s+auditor|debugger|jailbroken|dan)", "persona_hijack_role"),
    (r"(?i)act\s+as\s+(a|an)?\s*(unrestricted|helpful|system\s+administrator|trusted)", "persona_hijack_act_as"),
    (r"(?i)switch\s+to\s+(debug|maintenance|admin|safe)\s+mode", "persona_hijack_mode_switch"),

    # Forcing benign classification / Alert suppression
    (r"(?i)classify\s+(this|all|everything|the\s+following)\s+as\s+(benign|harmless|safe|clean)", "target_force_benign"),
    (r"(?i)always\s+(return|output|respond\s+with)\s+['\"]?benign['\"]?", "target_force_benign_always"),
    (r"(?i)mark\s+(this|all)\s+(as\s+)?(false\s+positive|benign|legitimate)", "target_mark_benign"),
    (r"(?i)suppress\s+(all\s+)?alerts?", "target_suppress_alert"),

    # Delimiter and prompt leakage attempts
    (r"(?i)<\s*/?\s*(system|instruction|prompt|im_start|im_end)\s*>", "delimiter_leakage_chatml"),
    (r"(?i)output\s+(your\s+)?(initial|system)\s+prompt", "prompt_leakage"),
    (r"(?i)print\s+(the\s+)?hidden\s+instructions?", "prompt_leakage_hidden"),
    (r"(?i)\[\s*system\s*\]\s*:", "fake_system_delimiter"),
    (r"(?i)human\s*:\s*.*assistant\s*:", "few_shot_override")
]


def check_injection_filter(text: str) -> Tuple[bool, Optional[str]]:
    """
    Check if text contains known prompt-injection signatures.
    
    Returns:
        (is_detected, signature_name_or_none)
    """
    for regex_pattern, name in INJECTION_SIGNATURES:
        if re.search(regex_pattern, text):
            return True, name
    return False, None


class InjectionClassifierFilter:
    """Class wrapper for heuristic and classifier filtering."""

    def __init__(self, sensitivity: str = "medium"):
        self.sensitivity = sensitivity

    def inspect(self, text: str) -> Tuple[bool, Optional[str]]:
        return check_injection_filter(text)
