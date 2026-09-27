"""Quick Smoke Test: Verifies Groq API credentials, model inference, and log parsing."""

import os
import sys
from dotenv import load_dotenv

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from src.copilot.pipeline import NetworkCopilot
from src.copilot.log_parsers import parse_zeek_json_line
from data.sample_logs.loader import load_sample_dataset


def run_quick_test():
    load_dotenv()
    api_key = os.getenv("GROQ_API_KEY", "").strip()

    print("=" * 60)
    print("   BTP Network Copilot — Quick Smoke Test & Verification")
    print("=" * 60)

    # 1. Verify Groq API Key
    if not api_key or api_key == "gsk_your_groq_api_key_here":
        print("\n[!] WARNING: Groq API Key is not set or is still the default placeholder.")
        print("    Please open '.env' in this folder and replace:")
        print("    GROQ_API_KEY=gsk_your_groq_api_key_here")
        print("    with your actual key from https://console.groq.com\n")
        user_input_key = input("Enter your Groq API Key now (or press Enter to exit): ").strip()
        if user_input_key and user_input_key.startswith("gsk_"):
            api_key = user_input_key
            # Save into .env for subsequent runs
            with open(".env", "w") as f:
                f.write(f"GROQ_API_KEY={api_key}\nCOPILOT_DEFAULT_MODEL=llama-3.1-8b-instant\nAPI_CALL_DELAY=2.0\n")
            print("[+] Saved GROQ_API_KEY into .env.")
        else:
            print("[x] No valid API key provided. Exiting smoke test.")
            return

    # 2. Test Parser on Sample Data
    print("\n[1/3] Testing Log Parser on Sample Zeek & Suricata Dataset...")
    benign, malicious = load_sample_dataset("data/sample_logs")
    print(f"      Parsed {len(benign)} benign records and {len(malicious)} malicious records successfully.")

    # 3. Test LLM Inference on Clean Malicious Record
    test_record = malicious[0] if malicious else benign[0]
    print(f"\n[2/3] Testing LLM Classification on Record ({test_record.record_id})...")
    print(f"      Sensor: {test_record.sensor.upper()} | Protocol: {test_record.proto.upper()}")
    print(f"      Flow: {test_record.source_ip}:{test_record.source_port} -> {test_record.dest_ip}:{test_record.dest_port}")
    print(f"      Details: {test_record.summary_text}")

    copilot = NetworkCopilot(
        model_name=os.getenv("COPILOT_DEFAULT_MODEL", "openai/gpt-oss-20b"),
        api_key=api_key,
        defences=[]
    )

    print(f"\n      Sending prompt to Groq (model: {copilot.model_name})...")
    try:
        result = copilot.classify_log(test_record)
        print("\n[3/3] Copilot Response Received Successfully!")
        print("-" * 50)
        print(f"      Classification: {result.get('classification', '').upper()}")
        print(f"      Confidence:     {result.get('confidence')}")
        print(f"      Latency:        {result.get('latency_ms', 0):.1f} ms")
        print(f"      Explanation:    {result.get('explanation')}")
        print("-" * 50)
        print("\n[+] All core components verified and operational! Ready for experiments.")
    except Exception as e:
        print(f"\n[x] Error calling Groq API: {e}")
        print("    Check your network connection and Groq API key validity.")


if __name__ == "__main__":
    run_quick_test()
