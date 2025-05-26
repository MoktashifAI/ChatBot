import time
import numpy as np
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

class PineconeMemoryStore:
    """
    Pinecone-backed semantic memory store for chat messages.
    Stores messages with embeddings for semantic search.
    """
    def __init__(self, api_key=None, index_name="trial", dimension=384):
        # Use provided API key or get from environment
        self.api_key = api_key or os.getenv("PINECONE_API_KEY")
        if not self.api_key:
            raise ValueError("Pinecone API key is required")
            
        # Initialize Pinecone
        self.pc = Pinecone(api_key=self.api_key)
        self.index = self.pc.Index(index_name)
        
        # Initialize the embedding model
        self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        
        print(f"PineconeMemoryStore initialized with index: {index_name}")
    
    def embed(self, texts):
        """Generate embeddings for the given texts."""
        return self.embedder.encode(texts, convert_to_numpy=True)
    
    def add(self, user_id, conversation_id, text, role, extra=None):
        """Add a message to memory."""
        # Create a unique ID for the vector
        vector_id = f"{user_id}_{conversation_id}_{int(time.time())}"
        
        # Prepare metadata
        metadata = {
            "user_id": str(user_id),
            "conversation_id": str(conversation_id),
            "role": role,
            "text": text,
            "timestamp": time.time(),
        }
        
        # Handle extra metadata, ensuring all values are compatible with Pinecone
        if extra:
            for key, value in extra.items():
                # Convert complex objects to strings to comply with Pinecone's requirements
                if isinstance(value, (dict, list)) and key != "tags":  # tags can be a list of strings
                    import json
                    try:
                        # For replyTo or other complex objects, store a string representation
                        if key == "replyTo" and isinstance(value, dict):
                            # For replyTo, just store the message ID if available, or a truncated content
                            if "_id" in value:
                                metadata[key] = str(value["_id"])
                            elif "content" in value and isinstance(value["content"], str):
                                # Store a truncated version of the content
                                metadata[key] = value["content"][:100] + "..." if len(value["content"]) > 100 else value["content"]
                            else:
                                # Last resort: convert to JSON string
                                metadata[key] = json.dumps(value)[:250]  # Limit length
                        else:
                            # For other complex objects, convert to JSON string with length limit
                            metadata[key] = json.dumps(value)[:250]  # Limit length
                    except (TypeError, ValueError):
                        # If JSON conversion fails, use string representation
                        metadata[key] = str(value)[:250]  # Limit length
                elif isinstance(value, list) and all(isinstance(item, str) for item in value):
                    # Lists of strings are allowed in Pinecone
                    metadata[key] = value
                else:
                    # For simple types (strings, numbers, booleans), use as is
                    metadata[key] = value
        
        # Get embedding and upsert to Pinecone
        embedding = self.embed([text])[0].tolist()
        self.index.upsert(vectors=[(vector_id, embedding, metadata)])
        
        print(f"Added memory: user={user_id}, conversation={conversation_id}, role={role}")
        return vector_id
    
    def search(self, user_id, query, conversation_id=None, top_k=3):
        """Semantic search for relevant messages. Optionally filter by conversation."""
        # Create filter for the query
        filter_dict = {"user_id": {"$eq": str(user_id)}}
        if conversation_id:
            filter_dict["conversation_id"] = {"$eq": str(conversation_id)}
        
        # Get query embedding and search
        query_embedding = self.embed([query])[0].tolist()
        results = self.index.query(
            vector=query_embedding,
            filter=filter_dict,
            top_k=top_k,
            include_metadata=True
        )
        
        # Format results similar to MongoDB implementation
        return [match["metadata"] for match in results["matches"]]
    
    def get_conversation_ids(self, user_id):
        """Return all conversation IDs for a user."""
        # This is a simplified approach - for production, you might want to 
        # implement a more efficient method to track conversation IDs
        
        # First, get a sample of vectors for this user to see if any exist
        sample_results = self.index.query(
            vector=[0.0] * 384,  # Dummy vector
            filter={"user_id": {"$eq": str(user_id)}},
            top_k=100,
            include_metadata=True
        )
        
        # Extract unique conversation IDs
        conversation_ids = set()
        for match in sample_results["matches"]:
            if "metadata" in match and "conversation_id" in match["metadata"]:
                conversation_ids.add(match["metadata"]["conversation_id"])
        
        return list(conversation_ids)
    
    def get_relevant_memories(self, user_id, query, current_convo_id):
        """Return relevant memories from current and other conversations for a user.
        Enhanced to provide better cross-conversation context retrieval.
        """
        # Get memories from current conversation
        current_results = self.search(user_id, query, conversation_id=current_convo_id)
        
        # Get memories from other conversations with higher top_k
        all_results = self.search(user_id, query, top_k=20)  # Increased from 10 to 20
        other_results = [r for r in all_results if r.get("conversation_id") != current_convo_id]
        
        # Try alternative query formulations to improve recall
        # This helps when the original query might not match semantically
        alternative_queries = [
            f"information about {query}",
            f"context for {query}",
            f"remember {query}"
        ]
        
        alt_results = []
        for alt_query in alternative_queries:
            alt_search = self.search(user_id, alt_query, top_k=10)
            # Only add results that aren't in the current conversation
            alt_results.extend([r for r in alt_search if r.get("conversation_id") != current_convo_id])
        
        # Combine and deduplicate results
        seen_texts = set()
        unique_other_results = []
        
        # First add the direct search results
        for result in other_results:
            text = result.get("text", "")
            if text and text not in seen_texts:
                seen_texts.add(text)
                unique_other_results.append(result)
        
        # Then add alternative query results if not already included
        for result in alt_results:
            text = result.get("text", "")
            if text and text not in seen_texts:
                seen_texts.add(text)
                unique_other_results.append(result)
        
        # Sort by relevance (if we have scores)
        if unique_other_results and "score" in unique_other_results[0]:
            unique_other_results.sort(key=lambda x: x.get("score", 0), reverse=True)
        
        # Get the top results (increased from 3 to 5)
        final_other_results = unique_other_results[:5]
        
        print(f"Retrieved memories: {len(current_results)} from current conversation, {len(final_other_results)} from other conversations")
        print(f"Alternative queries found {len(alt_results)} additional potential matches")
        
        return {
            "current": current_results,
            "other": final_other_results
        }
