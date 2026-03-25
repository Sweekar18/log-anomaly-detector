"""
Log Anomaly Detector — CLI Entrypoint

Usage:
    python main.py --log data/sample_logs/apache.log --query "any 500 errors?"
    python main.py --log data/sample_logs/syslog.log --query "failed login attempts"
"""

import argparse
import json

from src.ingestion import ingest
from src.embeddings import VectorStore
from src.rag import RAGDetector


def main():
    parser = argparse.ArgumentParser(description="Log Anomaly Detector")
    parser.add_argument("--log",   required=True, help="Path to log file")
    parser.add_argument("--query", required=True, help="Natural language query")
    parser.add_argument("--topk",  type=int, default=5, help="Top-k log entries to retrieve")
    parser.add_argument("--token", default=None, help="Hugging Face API token (or set HF_TOKEN env var)")
    args = parser.parse_args()

    print(f"\n📂 Ingesting logs from: {args.log}")
    entries = ingest(args.log)
    print(f"✅ Parsed {len(entries)} log entries\n")

    if not entries:
        print("❌ No valid log entries found. Check the file format.")
        return

    print("🔢 Building vector index...")
    store = VectorStore()
    store.build(entries)
    print("✅ FAISS index ready\n")

    detector = RAGDetector(store, hf_token=args.token)

    print(f"🔍 Query: {args.query}")
    print("-" * 50)
    result = detector.query(args.query, top_k=args.topk)

    print(json.dumps(result, indent=2))

    # Summary
    print("\n" + "=" * 50)
    status = "🚨 ANOMALY DETECTED" if result["anomaly_detected"] else "✅ No anomaly detected"
    print(f"{status} | Severity: {result.get('severity', 'N/A')}")
    print(f"💬 {result.get('explanation', '')}")
    print("=" * 50)


if __name__ == "__main__":
    main()
