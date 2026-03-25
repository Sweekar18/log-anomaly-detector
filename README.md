# Log Anomaly Detector 🔍
**LLM-Powered Security Analytics Tool**

An agentic log analysis pipeline that ingests server logs, embeds them using Hugging Face sentence transformers, stores vectors in FAISS, and uses a RAG-based LLM interface to detect anomalies and surface security events.

---

## Architecture

```
Log File (Apache / syslog)
        │
        ▼
   [ Ingestion ]          ← src/ingestion.py
   Parse & classify
        │
        ▼
   [ Embeddings ]         ← src/embeddings.py
   Encode with HF
   sentence-transformers
   → Store in FAISS
        │
        ▼
   [ RAG Detector ]       ← src/rag.py
   Retrieve top-k logs
   → LLM classifies
     anomaly + severity
        │
        ▼
   JSON Result
```

---

## Features

- ✅ Supports **Apache access logs** and **syslog** format (auto-detected)
- ✅ **Semantic retrieval** via FAISS + sentence-transformers (`all-MiniLM-L6-v2`)
- ✅ **RAG-based query interface** — ask in natural language
- ✅ **Agentic LLM refinement loop** — iteratively re-examines low-confidence results
- ✅ **Heuristic fallback** — works without an API token using rule-based detection
- ✅ **Pytest test suite** — covers ingestion, edge cases, malformed inputs

---

## Setup

```bash
git clone https://github.com/Sweekar18/log-anomaly-detector.git
cd log-anomaly-detector
pip install -r requirements.txt
```

---

## Usage

```bash
# With Hugging Face API token (LLM-powered)
python main.py --log data/sample_logs/apache.log \
               --query "any brute force login attempts?" \
               --token hf_your_token_here

# Without token (heuristic fallback)
python main.py --log data/sample_logs/syslog.log \
               --query "any disk or memory errors?"
```

### Example Output

```json
{
  "anomaly_detected": true,
  "severity": "HIGH",
  "explanation": "Multiple 401 failures from same IP suggest brute force attack.",
  "suspicious_entries": [
    "10.0.0.5 - POST /login -> 401",
    "10.0.0.5 - POST /login -> 500"
  ],
  "context_used": [...]
}
```

---

## Run Tests

```bash
pytest tests/ -v
# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing
```

---

## Project Structure

```
log-anomaly-detector/
├── main.py                        # CLI entrypoint
├── requirements.txt
├── src/
│   ├── ingestion.py               # Log parsing pipeline
│   ├── embeddings.py              # FAISS vector store
│   └── rag.py                     # RAG + LLM anomaly detection
├── tests/
│   └── test_pipeline.py           # Pytest suite (16 tests)
└── data/
    └── sample_logs/
        ├── apache.log
        └── syslog.log
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Embedding model | `all-MiniLM-L6-v2` (Hugging Face) |
| Vector store | FAISS |
| LLM | Mistral-7B via Hugging Face Inference API |
| Orchestration | LangChain-style agentic loop |
| Testing | Pytest |
| Log formats | Apache Combined, syslog |
