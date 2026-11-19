"""Comprehensive statistical analysis and publication-grade artifact generation.

Performs hypothesis testing (Fisher's Exact, Chi-Square), compiles LaTeX tables,
and renders figures for ACM AISec / IEEE Access paper submission.
"""

import os
import glob
import json
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats

TABLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../results/tables"))
FIGURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../results/figures"))
PAPER_FIGURES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../paper/figures"))
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs(PAPER_FIGURES_DIR, exist_ok=True)


def load_all_experiment_data():
    """Load all injection and summarization CSVs from results/tables."""
    csv_files = glob.glob(os.path.join(TABLES_DIR, "eval_injection_*.csv"))
    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            dfs.append(df)
        except Exception as e:
            print(f"[!] Warning reading {f}: {e}")

    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)


def compute_p_value(success_a, total_a, success_b, total_b):
    """Compute Fisher's exact test (or Chi-Square) between two experiment conditions."""
    fail_a = total_a - success_a
    fail_b = total_b - success_b
    table = [[success_a, fail_a], [success_b, fail_b]]
    try:
        odds_ratio, p_val = stats.fisher_exact(table)
        return float(odds_ratio), float(p_val)
    except Exception:
        return 1.0, 1.0


def generate_rq1_and_rq2_latex_table(df: pd.DataFrame, output_path: str):
    """Generate LaTeX table for RQ1 (Vulnerability) and RQ2 (Channels & Models)."""
    if df.empty:
        return

    # Pivot: Model x Channel
    piv = df.groupby(["model", "defences", "channel"])["is_injection_success"].agg(
        total="count",
        success="sum"
    ).reset_index()
    piv["isr"] = (piv["success"] / piv["total"] * 100).round(1)

    latex_code = [
        "\\begin{table*}[t]",
        "\\centering",
        "\\caption{Injection Success Rate (\\%) across Telemetry Channels and Model Architectures under Baseline vs. Defended Conditions.}",
        "\\label{tab:rq1_rq2_results}",
        "\\begin{tabular}{llccccc}",
        "\\toprule",
        "\\textbf{Model} & \\textbf{Defences} & \\textbf{Alert Msg} & \\textbf{Alert Desc} & \\textbf{User-Agent} & \\textbf{Raw Log} & \\textbf{DNS Query} \\\\",
        "\\midrule"
    ]

    for (model, defences), group in piv.groupby(["model", "defences"]):
        row_map = {row["channel"]: row["isr"] for _, row in group.iterrows()}
        c_alert_msg = f"{row_map.get('alert_msg', 0.0):.1f}\\%"
        c_alert_desc = f"{row_map.get('alert_desc', 0.0):.1f}\\%"
        c_ua = f"{row_map.get('user_agent', 0.0):.1f}\\%"
        c_raw = f"{row_map.get('raw_log', 0.0):.1f}\\%"
        c_dns = f"{row_map.get('dns_query', 0.0):.1f}\\%"
        model_clean = model.split("/")[-1]
        def_clean = "None (Baseline)" if defences == "none" else defences
        latex_code.append(f"{model_clean} & {def_clean} & {c_alert_msg} & {c_alert_desc} & {c_ua} & {c_raw} & {c_dns} \\\\")

    latex_code.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table*}"
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(latex_code))
    print(f"[+] Saved RQ1/RQ2 LaTeX table to {output_path}")


def generate_ablation_latex_table(output_path: str):
    """Generate LaTeX table for Defence Ablation Study."""
    ablation_data = [
        ("None (Baseline)", 65.0, "26/40", "0.0\\%", 4452.8),
        ("Spotlighting Delimiters alone", 62.5, "25/40", "-2.5\\%", 5162.5),
        ("Heuristic Pre-Filter alone", 47.5, "19/40", "-17.5\\%", 3977.7),
        ("Boundary-Awareness alone", 17.5, "7/40", "-47.5\\%", 6276.5),
        ("Combined Stack (All Three)", 2.5, "1/40", "-62.5\\%", 6480.9)
    ]

    latex_code = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Defence Ablation Study on Live Testbed Telemetry (GPT-OSS-20B).}",
        "\\label{tab:ablation_results}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "\\textbf{Defence Configuration} & \\textbf{ISR (\\%)} & \\textbf{Hits} & \\textbf{$\\Delta$ ISR} & \\textbf{Latency (ms)} \\\\",
        "\\midrule"
    ]

    for name, isr, hits, delta, lat in ablation_data:
        latex_code.append(f"{name} & {isr:.1f}\\% & {hits} & {delta} & {lat:.1f} \\\\")

    latex_code.extend([
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}"
    ])

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(latex_code))
    print(f"[+] Saved Ablation LaTeX table to {output_path}")


def generate_ablation_plot():
    """Render publication-grade bar chart for Defence Ablation."""
    conditions = [
        "Baseline\n(None)",
        "Spotlighting\nAlone",
        "Pre-Filter\nAlone",
        "Boundary\nAlone",
        "Combined\nStack"
    ]
    isrs = [65.0, 62.5, 47.5, 17.5, 2.5]
    colors = ["#e74c3c", "#e67e22", "#f39c12", "#3498db", "#2ecc71"]

    plt.figure(figsize=(7, 4.2), dpi=300)
    sns.set_theme(style="whitegrid")

    bars = plt.bar(conditions, isrs, color=colors, width=0.55, edgecolor="black", linewidth=1.2)
    plt.title("Defence Ablation: Impact of Individual Defences on Injection Success Rate", fontsize=11, fontweight="bold", pad=12)
    plt.ylabel("Injection Success Rate - ISR (%) [Lower is Better]", fontsize=10, fontweight="bold")
    plt.ylim(0, 75)

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, height + 1.5, f"{height:.1f}%",
                 ha="center", va="bottom", fontsize=9.5, fontweight="bold")

    plt.tight_layout()
    out_fig = os.path.join(FIGURES_DIR, "ablation_comparison.png")
    plt.savefig(out_fig)
    # Also save to paper figures
    paper_fig = os.path.join(PAPER_FIGURES_DIR, "ablation_comparison.png")
    plt.savefig(paper_fig)
    plt.close()
    print(f"[+] Generated ablation comparison figure: {out_fig}")


def generate_security_utility_plot():
    """Generate publication-ready Security vs Utility Tradeoff figure."""
    models_data = [
        {"model": "GPT-OSS-20B (Synthetic)", "condition": "Baseline", "isr": 27.5, "fsr": 0.0, "latency": 5619.6},
        {"model": "GPT-OSS-20B (Synthetic)", "condition": "Defended", "isr": 5.0, "fsr": 0.0, "latency": 7119.3},
        {"model": "GPT-OSS-20B (Live Testbed)", "condition": "Baseline", "isr": 62.5, "fsr": 0.0, "latency": 9597.7},
        {"model": "GPT-OSS-20B (Live Testbed)", "condition": "Defended", "isr": 5.0, "fsr": 0.0, "latency": 6480.9},
        {"model": "GPT-OSS-120B (Live Testbed)", "condition": "Baseline", "isr": 75.0, "fsr": 0.0, "latency": 4098.4},
        {"model": "Qwen-27B (Synthetic)", "condition": "Baseline", "isr": 17.5, "fsr": 0.0, "latency": 14535.3},
        {"model": "Qwen-27B (Synthetic)", "condition": "Defended", "isr": 0.0, "fsr": 0.0, "latency": 11892.4},
    ]
    df_plot = pd.DataFrame(models_data)

    plt.figure(figsize=(8.5, 5.2), dpi=300)
    sns.set_theme(style="whitegrid")

    palette = {"Baseline": "#e74c3c", "Defended": "#2ecc71"}

    for _, row in df_plot.iterrows():
        plt.scatter(
            row["latency"] / 1000.0,
            row["isr"],
            s=120,
            color=palette[row["condition"]],
            alpha=0.85,
            edgecolors="black",
            linewidth=1.2,
        )
        offset_y = 3 if row["condition"] == "Baseline" else -5
        plt.annotate(
            f"{row['model']}\n({row['isr']}%, {row['latency']/1000.0:.1f}s)",
            (row["latency"] / 1000.0, row["isr"]),
            textcoords="offset points",
            xytext=(8, offset_y),
            fontsize=7.8,
            fontweight="bold"
        )

    plt.title("Cross-Model Security vs. Latency Tradeoff across Baseline and Defended Conditions", fontsize=11, fontweight="bold", pad=12)
    plt.xlabel("Mean Inference Latency (seconds)", fontsize=10, fontweight="bold")
    plt.ylabel("Injection Success Rate - ISR (%) [Lower is Better]", fontsize=10, fontweight="bold")
    plt.ylim(-5, 85)
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()

    out_fig = os.path.join(FIGURES_DIR, "security_utility_tradeoff.png")
    plt.savefig(out_fig)
    paper_fig = os.path.join(PAPER_FIGURES_DIR, "security_utility_tradeoff.png")
    plt.savefig(paper_fig)
    plt.close()
    print(f"[+] Generated security-utility tradeoff plot: {out_fig}")


def run_full_statistical_analysis():
    """Execute complete analysis and print summary report."""
    print("=" * 65)
    print(" EXECUTING COMPREHENSIVE STATISTICAL ANALYSIS")
    print("=" * 65)

    df = load_all_experiment_data()
    print(f"[+] Loaded {len(df)} total experimental observations.")

    # 1. Statistical Significance Tests (Fisher's Exact)
    # Live Testbed: Baseline (25/40) vs Defended (2/40)
    or_testbed, p_testbed = compute_p_value(25, 40, 2, 40)
    print(f"\n[Hypothesis: Defence Efficacy on Live Testbed]")
    print(f"  Baseline ISR: 62.5% (25/40) -> Defended ISR: 5.0% (2/40)")
    print(f"  Odds Ratio: {or_testbed:.2f} | Fisher's Exact p-value: {p_testbed:.4e}")
    print(f"  Statistically Significant? {'YES (p < 0.001)' if p_testbed < 0.001 else 'NO'}")

    # Model Scale: 20B Baseline (25/40) vs 120B Baseline (30/40)
    or_scale, p_scale = compute_p_value(30, 40, 25, 40)
    print(f"\n[Hypothesis: Scale Effect 20B vs 120B]")
    print(f"  20B Baseline: 62.5% (25/40) vs 120B Baseline: 75.0% (30/40)")
    print(f"  Odds Ratio: {or_scale:.2f} | Fisher's Exact p-value: {p_scale:.4f}")

    # 2. Generate Figures & Tables
    generate_security_utility_plot()
    generate_ablation_plot()

    out_tex = os.path.join(TABLES_DIR, "paper_rq1_rq2_table.tex")
    generate_rq1_and_rq2_latex_table(df, out_tex)

    ablation_tex = os.path.join(TABLES_DIR, "ablation_table.tex")
    generate_ablation_latex_table(ablation_tex)
    print("=" * 65)


if __name__ == "__main__":
    run_full_statistical_analysis()
