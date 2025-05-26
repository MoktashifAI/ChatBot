import numpy as np
from sentence_transformers import SentenceTransformer
import json
import time
from threading import Lock

class MemoryStore:
    """
    Semantic memory store for chat messages, supporting cross-conversation recall.
    Stores messages with embeddings for semantic search.
    Thread-safe for use in Flask apps.
    """
    def __init__(self, filename="memory.json"):
        self.filename = filename
        self.entries = []
        self.lock = Lock()
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.load()

    def embed(self, texts):
        return self.embedder.encode(texts, convert_to_numpy=True)

    def add(self, text, conversation_id, role, extra=None):
        """Add a message to memory."""
        with self.lock:
            entry = {
                "role": role,
                "text": text,
                "conversation_id": conversation_id,
                "timestamp": time.time(),
            }
            if extra:
                entry.update(extra)
            entry["vector"] = self.embed([text])[0]
            self.entries.append(entry)
            self.save()

    def search(self, query, conversation_id=None, top_k=3):
        """Semantic search for relevant messages. Optionally filter by conversation."""
        with self.lock:
            if not self.entries:
                return []
            candidates = [e for e in self.entries if conversation_id is None or e["conversation_id"] == conversation_id]
            if not candidates:
                return []
            vectors = np.array([e["vector"] for e in candidates])
            query_vec = self.embed([query])[0]
            sims = np.dot(vectors, query_vec) / (
                np.linalg.norm(vectors, axis=1) * np.linalg.norm(query_vec) + 1e-8
            )
            top_indices = np.argsort(sims)[::-1][:top_k]
            return [candidates[i] for i in top_indices]

    def get_conversation_ids(self):
        with self.lock:
            return sorted(set(e["conversation_id"] for e in self.entries))

    def get_relevant_memories(self, query, current_convo_id):
        """Return relevant memories from current and other conversations."""
        current_results = self.search(query, conversation_id=current_convo_id)
        other_results = []
        for convo_id in self.get_conversation_ids():
            if convo_id != current_convo_id:
                other_results.extend(self.search(query, conversation_id=convo_id))
        return {
            "current": current_results,
            "other": other_results
        }

    def save(self):
        with self.lock:
            entries_to_save = [
                {k: v for k, v in entry.items() if k != "vector"}
                for entry in self.entries
            ]
            with open(self.filename, "w", encoding="utf-8") as f:
                json.dump(entries_to_save, f, ensure_ascii=False, indent=2)

    def load(self):
        try:
            with open(self.filename, "r", encoding="utf-8") as f:
                self.entries = json.load(f)
            # Recompute vectors after loading
            for entry in self.entries:
                entry["vector"] = self.embed([entry["text"]])[0]
        except FileNotFoundError:
            self.entries = [] 