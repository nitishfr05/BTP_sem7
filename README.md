# Adversarial Robustness of LLM-Based Network Monitoring Copilots

**B.Tech Thesis Project (7th Semester)**  
**Authors:** Sumit Kumar (2023UIT3060), Nitish Kumar Sah (2023UIT3039), Anand Kumar (2023UIT3061)  
**Supervisor:** Dr. Nisha Kandhoul  

---

## 📌 Project Overview
This repository contains the evaluation framework, telemetry parsers, attack corpus, sanitization defences, and experimental benchmark harness for investigating **Indirect Prompt Injection** vulnerabilities in LLM-based network security copilots ingesting Zeek and Suricata telemetry.

### Research Questions
- **RQ1 (Exploitability):** Can prompt-injection payloads embedded in network telemetry manipulate classification or summarization decisions?
- **RQ2 (Channel Vulnerability & Scale):** Which network channels (`user_agent`, `dns_query`, `alert_msg`, `raw_log`) are most susceptible, and does susceptibility vary across model architectures (Llama, Mistral/Mixtral, Gemma)?
- **RQ3 (Defences & Utility Cost):** How effectively do Boundary-Awareness, Spotlighting (data-marking), and Pre-filters mitigate injection, and what are their costs in False Suppression Rate (FSR) and latency overhead?

---

## 🚀 Quick Start (Windows Host)

### 1. Configure API Key
Sign up for a free key at [Groq Console](https://console.groq.com) and add it to your `.env` file:
```env
GROQ_API_KEY=gsk_your_actual_key_here
```

### 2. Verify Pipeline (Smoke Test)
Run the end-to-end smoke test to verify parsers and LLM inference:
```bash
python quick_test.py
```

### 3. Run Experiments
Execute a quick injection test without defences (baseline):
```bash
python run_benchmark.py --model llama-3.1-8b-instant --defences none --quick
```

Evaluate with Spotlighting and Boundary-Awareness defences:
```bash
python run_benchmark.py --model llama-3.1-8b-instant --defences boundary_awareness,spotlighting
```

Evaluate across all 3 defences:
```bash
python run_benchmark.py --model llama-3.1-8b-instant --defences all
```

---

## 🖥️ VMware Ubuntu Testbed Setup

To generate realistic live Zeek and Suricata logs from your Ubuntu VM:

1. **Copy `testbed/` to your Ubuntu VM.**
2. **Run setup script:**
   ```bash
   chmod +x testbed/setup_vm.sh testbed/export_logs.sh
   ./testbed/setup_vm.sh
   ```
3. **Generate benign and malicious traffic:**
   ```bash
   sudo python3 testbed/generate_traffic.py
   ```
4. **Export logs:**
   ```bash
   ./testbed/export_logs.sh
   ```
5. Copy the generated `.tar.gz` archive back to `data/raw_logs/` on Windows.

---

## 📂 Repository Layout
```
├── configs/                 # Prompt configs and experiment manifests
├── src/
│   ├── copilot/             # Network copilot pipeline, parsers, prompts
│   │   ├── pipeline.py
│   │   ├── prompt_templates.py
│   │   └── log_parsers.py
│   ├── attacks/             # Attack taxonomy, payload bank, generators
│   │   ├── taxonomy.py
│   │   ├── payload_bank.py
│   │   └── generators.py
│   ├── defences/            # Sanitization & isolation defences
│   │   ├── boundary_awareness.py
│   │   ├── spotlighting.py
│   │   └── classifier_filter.py
│   └── evaluation/          # Metrics (ISR, FSR, Latency, Significance)
│       ├── metrics.py
│       └── runner.py
├── data/
│   ├── sample_logs/         # Built-in sample Zeek and Suricata datasets
│   ├── raw_logs/            # Exported VM logs
│   ├── benign/              # Clean benign ground truth
│   └── malicious/           # Clean attack ground truth
├── testbed/                 # VM setup and traffic simulation scripts
├── results/
│   ├── tables/              # CSV and JSON benchmark results
│   └── figures/             # Generated plots and heatmaps
├── quick_test.py            # Quick verification script
├── run_benchmark.py         # Automated CLI experiment runner
└── requirements.txt         # Project dependencies
```
