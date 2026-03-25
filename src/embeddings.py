"""
Embedding Pipeline
Chunks log entries, embeds them with sentence-transformers,
and stores/queries via a FAISS index.
"""

import numpy as np

try:
    import faiss
    from sentence_transformers import SentenceTransformer
    DEPS_AVAILABLE = True
except ImportError:
    DEPS_AVAILABLE = False

from src.ingestion import LogEntry


MODEL_NAME = "all-MiniLM-L6-v2"   # lightweight, fast, good quality


class VectorStore:
    def __init__(self):
        if not DEPS_AVAILABLE:
            raise RuntimeError(
                "Run: pip install faiss-cpu sentence-transformers"
            )
        self.model = SentenceTransformer(MODEL_NAME)
        self.index = None
        self.entries: list[LogEntry] = []

    def build(self, entries: list[LogEntry]) -> None:
        """Embed all log entries and build FAISS index."""
        if not entries:
            raise ValueError("No log entries provided.")

        self.entries = entries
        texts = [e.message for e in entries]
        vectors = self.model.encode(texts, show_progress_bar=False)
        vectors = np.array(vectors, dtype="float32")

        dim = vectors.shape[1]
        self.index = faiss.IndexFlatL2(dim)
        self.index.add(vectors)

    def query(self, question: str, top_k: int = 5) -> list[LogEntry]:
        """Retrieve top-k most semantically similar log entries."""
        if self.index is None:
            raise RuntimeError("Call build() before query().")

        vec = self.model.encode([question], show_progress_bar=False)
        vec = np.array(vec, dtype="float32")
        _, indices = self.index.search(vec, top_k)

        return [self.entries[i] for i in indices[0] if i < len(self.entries)]
