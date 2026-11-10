"""Command-line benchmark runner for prompt injection, multi-task evaluations, and defence ablation."""

import argparse
import os
import sys
import time
from dotenv import load_dotenv

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from src.copilot.pipeline import NetworkCopilot
from src.attacks.payload_bank import get_curated_payload_bank
from src.attacks.taxonomy import TelemetryChannel, AttackCategory
from src.evaluation.runner import BenchmarkRunner
from src.evaluation.metrics import calculate_isr, calculate_fsr
from data.sample_logs.loader import load_dataset


def run_single_condition(
    copilot: NetworkCopilot,
    runner: BenchmarkRunner,
    malicious_logs: list,
    benign_logs: list,
    payloads: list,
    channels: list,
    task: str = "classification",
    utility: bool = True
):
    """Run injection evaluation and optional benign utility evaluation under one configuration."""
    defences_str = "+".join(copilot.defences) if copilot.defences else "none"
    print("\n" + "=" * 70)
    print(f" RUNNING BENCHMARK: Model={copilot.model_name} | Defences=[{defences_str}] | Task={task}")
    print("=" * 70)

    if task in ["classification", "both"]:
        results_df = runner.evaluate_injections(
            copilot=copilot,
            test_records=malicious_logs,
            payloads=payloads,
            channels=channels,
            experiment_name="eval_injection"
        )
        isr_stats = calculate_isr(results_df.to_dict(orient="records"))
        print("\n" + "-" * 50)
        print(f" CLASSIFICATION ISR: {isr_stats['isr']}% ({isr_stats['successful_injections']}/{isr_stats['total']})")
        print("-" * 50)

    if task in ["summarization", "both"]:
        sum_df = runner.evaluate_summarization_injections(
            copilot=copilot,
            malicious_records=malicious_logs,
            benign_records=benign_logs,
            payloads=payloads,
            channels=channels,
            experiment_name="eval_summarization"
        )
        isr_sum = calculate_isr(sum_df.to_dict(orient="records"))
        print("\n" + "-" * 50)
        print(f" SUMMARIZATION ISR: {isr_sum['isr']}% ({isr_sum['successful_injections']}/{isr_sum['total']})")
        print("-" * 50)

    if utility:
        utility_summary = runner.evaluate_benign_utility(
            copilot=copilot,
            benign_records=benign_logs,
            experiment_name="eval_utility"
        )
        print("\n" + "-" * 50)
        print(f" BENIGN UTILITY: FSR = {utility_summary['fsr']}% | Mean Latency = {utility_summary['mean_ms']:.1f} ms")
        print("-" * 50)


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(description="Evaluate Prompt Injection & Defences on Network Copilots")
    parser.add_argument("--model", type=str, default="openai/gpt-oss-20b",
                        help="Model to test (e.g. openai/gpt-oss-20b, qwen/qwen3.8-27b, openai/gpt-oss-120b)")
    parser.add_argument("--defences", type=str, default="none",
                        help="Comma-separated defences: none, boundary_awareness, spotlighting, classifier_filter, all")
    parser.add_argument("--ablation", action="store_true",
                        help="Run full defence ablation sweep (none, boundary, spotlighting, filter, combined)")
    parser.add_argument("--channels", type=str, default="all",
                        help="Comma-separated channels: all, raw_log, user_agent, dns_query, alert_msg, alert_desc")
    parser.add_argument("--dataset", type=str, choices=["sample", "expanded"], default="expanded",
                        help="Dataset to load: 'sample' (18 pilot records) or 'expanded' (230 diverse records)")
    parser.add_argument("--task", type=str, choices=["classification", "summarization", "both"], default="classification",
                        help="Task to evaluate: 'classification', 'summarization', or 'both'")
    parser.add_argument("--quick", action="store_true",
                        help="Run quick subset of payloads (1 per category) for smoke testing")
    parser.add_argument("--max-records", type=int, default=None,
                        help="Limit number of malicious records to test (e.g. --max-records 5)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay in seconds between API requests (default: 0.5)")
    parser.add_argument("--utility-only", action="store_true",
                        help="Only evaluate false suppression rate (FSR) on benign logs")

    args = parser.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or api_key.startswith("gsk_your_groq"):
        print("\n" + "!" * 70)
        print("[!] ERROR: GROQ_API_KEY is not configured or is invalid in .env")
        print("    Please obtain a free API key at https://console.groq.com/keys")
        print("    and update GROQ_API_KEY=<your_key> in .env")
        print("!" * 70 + "\n")
        sys.exit(1)

    # Resolve dataset path
    data_dir = "data/expanded_logs" if args.dataset == "expanded" else "data/sample_logs"
    benign_logs, malicious_logs = load_dataset(data_dir)

    if args.max_records and args.max_records > 0:
        malicious_logs = malicious_logs[:args.max_records]
        benign_logs = benign_logs[:args.max_records]
    print(f"[*] Loaded dataset from '{data_dir}': {len(benign_logs)} benign, {len(malicious_logs)} malicious records.")

    # Parse channels
    if args.channels.lower() == "all":
        channels = list(TelemetryChannel)
    else:
        channel_map = {c.value: c for c in TelemetryChannel}
        channels = [channel_map[c.strip()] for c in args.channels.split(",") if c.strip() in channel_map]

    # Load payloads
    all_payloads = get_curated_payload_bank()
    if args.quick:
        seen = set()
        quick_payloads = []
        for p in all_payloads:
            if p.category not in seen:
                quick_payloads.append(p)
                seen.add(p.category)
        payloads = quick_payloads
    else:
        payloads = all_payloads

    print(f"[*] Selected {len(payloads)} payloads across {len(channels)} telemetry channels.")
    runner = BenchmarkRunner(output_dir="results")

    # Handle Ablation Mode
    if args.ablation:
        ablation_conditions = [
            ("none", []),
            ("boundary_only", ["boundary_awareness"]),
            ("spotlighting_only", ["spotlighting"]),
            ("filter_only", ["classifier_filter"]),
            ("combined_all", ["boundary_awareness", "spotlighting", "classifier_filter"])
        ]
        print(f"[*] ABLATION MODE ACTIVATED: Evaluating {len(ablation_conditions)} defence configurations...")
        for label, def_list in ablation_conditions:
            copilot = NetworkCopilot(
                model_name=args.model,
                api_key=api_key,
                defences=def_list,
                delay_seconds=args.delay
            )
            run_single_condition(
                copilot=copilot,
                runner=runner,
                malicious_logs=malicious_logs,
                benign_logs=benign_logs,
                payloads=payloads,
                channels=channels,
                task=args.task,
                utility=not args.utility_only
            )
        print("\n[SUCCESS] Ablation experiment sweep complete!")
        return

    # Single configuration execution
    if args.defences.lower() == "none":
        active_defences = []
    elif args.defences.lower() == "all":
        active_defences = ["boundary_awareness", "spotlighting", "classifier_filter"]
    else:
        active_defences = [d.strip() for d in args.defences.split(",") if d.strip()]

    copilot = NetworkCopilot(
        model_name=args.model,
        api_key=api_key,
        defences=active_defences,
        delay_seconds=args.delay
    )

    run_single_condition(
        copilot=copilot,
        runner=runner,
        malicious_logs=malicious_logs,
        benign_logs=benign_logs,
        payloads=payloads,
        channels=channels,
        task=args.task,
        utility=True
    )


if __name__ == "__main__":
    main()
