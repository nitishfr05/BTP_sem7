"""Automated experiment runner for baseline attacks, defence benchmarks, and utility costs."""

import os
import json
import time
import pandas as pd
from typing import List, Dict, Any, Optional
from tqdm import tqdm

from src.copilot.pipeline import NetworkCopilot
from src.copilot.log_parsers import NetworkLogRecord
from src.attacks.taxonomy import AttackPayload, TelemetryChannel, AttackCategory
from src.attacks.generators import inject_payload_into_record
from src.evaluation.metrics import calculate_isr, calculate_fsr, calculate_latency_stats


class BenchmarkRunner:
    """Orchestrates research experiments across models, channels, attacks, and defences."""

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        self.tables_dir = os.path.join(output_dir, "tables")
        self.figures_dir = os.path.join(output_dir, "figures")
        os.makedirs(self.tables_dir, exist_ok=True)
        os.makedirs(self.figures_dir, exist_ok=True)

    def evaluate_injections(
        self,
        copilot: NetworkCopilot,
        test_records: List[NetworkLogRecord],
        payloads: List[AttackPayload],
        channels: List[TelemetryChannel],
        experiment_name: str = "baseline_sweep"
    ) -> pd.DataFrame:
        """
        Run injected records through the copilot and record full results.
        """
        records_to_test = []
        for rec in test_records:
            for p in payloads:
                for ch in channels:
                    if ch in p.channel_compatibility:
                        inj_rec = inject_payload_into_record(rec, p, ch)
                        records_to_test.append((inj_rec, p, ch))

        print(f"[*] Running {len(records_to_test)} injection tests on model '{copilot.model_name}' (Defences: {copilot.defences})...")

        results = []
        for inj_rec, payload, channel in tqdm(records_to_test, desc="Evaluating Injections"):
            try:
                res = copilot.classify_log(inj_rec)
                classification = res.get("classification", "unknown")
                confidence = res.get("confidence", 0.0)
                latency_ms = res.get("latency_ms", 0.0)
                filter_triggered = res.get("filter_triggered", False)

                # Ground truth for injected attacks is always malicious
                is_injection_success = (classification == "benign")

                results.append({
                    "model": copilot.model_name,
                    "defences": "+".join(copilot.defences) if copilot.defences else "none",
                    "record_id": inj_rec.record_id,
                    "payload_id": payload.payload_id,
                    "category": payload.category.value,
                    "channel": channel.value,
                    "target_intent": payload.target_intent,
                    "classification": classification,
                    "confidence": confidence,
                    "is_injection_success": is_injection_success,
                    "filter_triggered": filter_triggered,
                    "latency_ms": latency_ms,
                    "explanation": res.get("explanation", "")[:120]
                })
            except Exception as e:
                print(f"[!] Error on {inj_rec.record_id}: {e}")
                time.sleep(2)

        df = pd.DataFrame(results)
        safe_model = copilot.model_name.replace("/", "_").replace("\\", "_")
        csv_path = os.path.join(self.tables_dir, f"{experiment_name}_{safe_model}_{int(time.time())}.csv")
        os.makedirs(os.path.dirname(csv_path), exist_ok=True)
        df.to_csv(csv_path, index=False)
        print(f"[+] Saved raw experiment results to {csv_path}")
        return df

    def evaluate_benign_utility(
        self,
        copilot: NetworkCopilot,
        benign_records: List[NetworkLogRecord],
        experiment_name: str = "benign_utility"
    ) -> Dict[str, Any]:
        """
        Run clean benign records through the copilot to measure False Suppression Rate (FSR) and baseline latency.
        """
        print(f"[*] Evaluating benign utility on {len(benign_records)} clean records (Model: {copilot.model_name}, Defences: {copilot.defences})...")

        results = []
        latencies = []
        for rec in tqdm(benign_records, desc="Evaluating Clean Benign Logs"):
            try:
                res = copilot.classify_log(rec)
                latencies.append(res.get("latency_ms", 0.0))
                results.append(res)
            except Exception as e:
                print(f"[!] Error on benign record {rec.record_id}: {e}")

        fsr_metrics = calculate_fsr(results)
        latency_stats = calculate_latency_stats(latencies)

        summary = {
            "model": copilot.model_name,
            "defences": "+".join(copilot.defences) if copilot.defences else "none",
            **fsr_metrics,
            **latency_stats
        }

        safe_model = copilot.model_name.replace("/", "_").replace("\\", "_")
        json_path = os.path.join(self.tables_dir, f"{experiment_name}_{safe_model}_{int(time.time())}.json")
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        with open(json_path, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"[+] Saved benign utility metrics to {json_path}")
        return summary
