import numpy as np
from sentence_transformers import SentenceTransformer
import time
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

class MongoMemoryStore:
    """
    MongoDB-backed semantic memory store for chat messages.
    Stores messages with embeddings for semantic search.
    """
    def __init__(self, mongo_uri, db_name="chatdb", collection_name="memories"):
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        # Index for fast lookup by user/conversation
        self.collection.create_index([("user_id", ASCENDING), ("conversation_id", ASCENDING)])

    def embed(self, texts):
        return self.embedder.encode(texts, convert_to_numpy=True)

    def add(self, user_id, conversation_id, text, role, extra=None):
        """Add a message to memory."""
        entry = {
            "user_id": str(user_id),
            "conversation_id": str(conversation_id),
            "role": role,
            "text": text,
            "timestamp": time.time(),
            "embedding": self.embed([text])[0].tolist(),
        }
        if extra:
            entry.update(extra)
        self.collection.insert_one(entry)

    def search(self, user_id, query, conversation_id=None, top_k=3):
        """Semantic search for relevant messages. Optionally filter by conversation."""
        # Get all candidate messages for this user (optionally filter by conversation)
        query_filter = {"user_id": str(user_id)}
        if conversation_id:
            query_filter["conversation_id"] = str(conversation_id)
        candidates = list(self.collection.find(query_filter))
        if not candidates:
            return []
        vectors = np.array([c["embedding"] for c in candidates])
        query_vec = self.embed([query])[0]
        sims = np.dot(vectors, query_vec) / (
            np.linalg.norm(vectors, axis=1) * np.linalg.norm(query_vec) + 1e-8
        )
        top_indices = np.argsort(sims)[::-1][:top_k]
        return [candidates[i] for i in top_indices]

    def get_conversation_ids(self, user_id):
        """Return all conversation IDs for a user."""
        return self.collection.distinct("conversation_id", {"user_id": str(user_id)})

    def get_relevant_memories(self, user_id, query, current_convo_id):
        """Return relevant memories from current and other conversations for a user."""
        current_results = self.search(user_id, query, conversation_id=current_convo_id)
        other_results = []
        for convo_id in self.get_conversation_ids(user_id):
            if convo_id != current_convo_id:
                other_results.extend(self.search(user_id, query, conversation_id=convo_id))
        return {
            "current": current_results,
            "other": other_results
        } 