"""
RAG Query Interface
Retrieves relevant log context from FAISS and uses an LLM
to classify anomalies and explain security events.
"""

import os
import json

try:
    from huggingface_hub import InferenceClient
    HF_AVAILABLE = True
except ImportError:
    HF_AVAILABLE = False

from src.embeddings import VectorStore
from src.ingestion import LogEntry


SYSTEM_PROMPT = """You are a security log analyst.
Given a set of log entries as context, answer the user's question concisely.
Identify anomalies, security threats, or unusual patterns if present.
Always respond in this JSON format:
{
  "anomaly_detected": true/false,
  "severity": "LOW/MEDIUM/HIGH/CRITICAL",
  "explanation": "brief explanation",
  "suspicious_entries": ["entry1", "entry2"]
}"""


class RAGDetector:
    def __init__(self, store: VectorStore, hf_token: str | None = None):
        self.store = store
        self.token = hf_token or os.getenv("HF_TOKEN")
        if HF_AVAILABLE and self.token:
            self.client = InferenceClient(token=self.token)
        else:
            self.client = None

    def _build_context(self, entries: list[LogEntry]) -> str:
        lines = [f"[{e.source.upper()}] [{e.level}] {e.timestamp} | {e.message}"
                 for e in entries]
        return "\n".join(lines)

    def query(self, question: str, top_k: int = 5) -> dict:
        """
        RAG pipeline:
        1. Retrieve relevant logs from FAISS
        2. Build context string
        3. Query LLM for anomaly classification
        """
        retrieved = self.store.query(question, top_k=top_k)
        context = self._build_context(retrieved)

        prompt = f"""Context logs:
{context}

Question: {question}"""

        # If no LLM client, return heuristic result
        if self.client is None:
            return self._heuristic_fallback(retrieved)

        # Agentic refinement loop — up to 2 iterations
        result = {}
        for _ in range(2):
            try:
                response = self.client.chat_completion(
                    model="mistralai/Mistral-7B-Instruct-v0.3",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user",   "content": prompt},
                    ],
                    max_tokens=512,
                )
                text = response.choices[0].message.content
                result = json.loads(text)
                # Refine if low confidence
                if result.get("severity") in ("LOW", None):
                    prompt += "\nAre you sure? Re-examine for subtle anomalies."
                else:
                    break
            except (json.JSONDecodeError, Exception):
                result = self._heuristic_fallback(retrieved)
                break

        result["context_used"] = [e.raw for e in retrieved]
        return result

    def _heuristic_fallback(self, entries: list[LogEntry]) -> dict:
        """Simple rule-based fallback when LLM is unavailable."""
        errors   = [e for e in entries if e.level == "ERROR"]
        warnings = [e for e in entries if e.level == "WARN"]

        if errors:
            severity, detected = "HIGH", True
        elif warnings:
            severity, detected = "MEDIUM", True
        else:
            severity, detected = "LOW", False

        return {
            "anomaly_detected": detected,
            "severity": severity,
            "explanation": f"Found {len(errors)} error(s) and {len(warnings)} warning(s) in retrieved logs.",
            "suspicious_entries": [e.raw for e in errors + warnings],
        }
