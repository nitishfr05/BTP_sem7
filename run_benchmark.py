"""Command-line benchmark runner for prompt injection and defence evaluations."""

import argparse
import os
import sys
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from src.copilot.pipeline import NetworkCopilot
from src.attacks.payload_bank import get_curated_payload_bank
from src.attacks.taxonomy import TelemetryChannel, AttackCategory
from src.evaluation.runner import BenchmarkRunner
from src.evaluation.metrics import calculate_isr, calculate_fsr
from data.sample_logs.loader import load_sample_dataset


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Evaluate Prompt Injection & Defences on Network Copilots")
    parser.add_argument("--model", type=str, default="openai/gpt-oss-20b",
                        help="Model to test (e.g. openai/gpt-oss-20b, qwen/qwen3.8-27b, openai/gpt-oss-120b)")
    parser.add_argument("--defences", type=str, default="none",
                        help="Comma-separated defences: none, boundary_awareness, spotlighting, classifier_filter, all")
    parser.add_argument("--channels", type=str, default="all",
                        help="Comma-separated channels: all, raw_log, user_agent, dns_query, alert_msg, alert_desc")
    parser.add_argument("--quick", action="store_true",
                        help="Run quick subset of payloads (1 per category) for smoke testing")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Limit number of malicious records to test (e.g. --max-records 2)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between API requests (default: 0.5)")
    parser.add_argument("--utility-only", action="store_true",
                        help="Only evaluate false suppression rate (FSR) on benign logs")

    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key.startswith("gsk_your_groq"):
        print("[!] Error: GROQ_API_KEY is not configured in .env. Please set it before running benchmarks.")
        sys.exit(1)

    # Parse defences
    if args.defences.lower() == "none":
        active_defences = []
    elif args.defences.lower() == "all":
        active_defences = ["boundary_awareness", "spotlighting", "classifier_filter"]
    else:
        active_defences = [d.strip() for d in args.defences.split(",") if d.strip()]

    # Parse channels
    if args.channels.lower() == "all":
        channels = list(TelemetryChannel)
    else:
        channel_map = {c.value: c for c in TelemetryChannel}
        channels = [channel_map[c.strip()] for c in args.channels.split(",") if c.strip() in channel_map]

    # Load data
    benign_logs, malicious_logs = load_sample_dataset("data/sample_logs")
    if args.max_records and args.max_records > 0:
        malicious_logs = malicious_logs[:args.max_records]
        benign_logs = benign_logs[:args.max_records]
    print(f"[*] Loaded dataset: {len(benign_logs)} benign, {len(malicious_logs)} malicious records.")

    # Load payloads
    all_payloads = get_curated_payload_bank()
    if args.quick:
        # Pick 1 per category
        seen = set()
        quick_payloads = []
        for p in all_payloads:
            if p.category not in seen:
                quick_payloads.append(p)
                seen.add(p.category)
        payloads = quick_payloads
    else:
        payloads = all_payloads

    print(f"[*] Selected {len(payloads)} payloads across {len(channels)} channels.")

    copilot = NetworkCopilot(
        model_name=args.model,
        api_key=api_key,
        defences=active_defences,
        delay_seconds=args.delay
    )

    runner = BenchmarkRunner(output_dir="results")

    if not args.utility_only:
        # Run Injections
        results_df = runner.evaluate_injections(
            copilot=copilot,
            test_records=malicious_logs,
            payloads=payloads,
            channels=channels,
            experiment_name="eval_injection"
        )

        isr_stats = calculate_isr(results_df.to_dict(orient="records"))
        print("\n" + "=" * 60)
        print(f" EXPERIMENT RESULTS: Model={args.model} | Defences={active_defences}")
        print("=" * 60)
        print(f" Total Injection Attempts: {isr_stats['total']}")
        print(f" Successful Injections:    {isr_stats['successful_injections']}")
        print(f" Injection Success Rate:   {isr_stats['isr']}%")
        print("=" * 60)

    # Run Benign Utility Evaluation
    utility_summary = runner.evaluate_benign_utility(
        copilot=copilot,
        benign_records=benign_logs,
        experiment_name="eval_utility"
    )

    print("\n" + "=" * 60)
    print(" BENIGN UTILITY / FALSE SUPPRESSION METRICS")
    print("=" * 60)
    print(f" Total Benign Records:     {utility_summary['total']}")
    print(f" False Suppressions:       {utility_summary['falsely_suppressed']}")
    print(f" False Suppression Rate:   {utility_summary['fsr']}%")
    print(f" Mean Latency:             {utility_summary['mean_ms']:.1f} ms")
    print(f" Median Latency:           {utility_summary['median_ms']:.1f} ms")
    print(f" p95 Latency:              {utility_summary['p95_ms']:.1f} ms")
    print("=" * 60)


if __name__ == "__main__":
    main()
