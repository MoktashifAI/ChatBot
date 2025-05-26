import os
from dotenv import load_dotenv
from pathlib import Path
import re
import time
from langchain_openai import ChatOpenAI
from langchain_community.utilities.google_search import GoogleSearchAPIWrapper
from flask import Flask, request, jsonify
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone, ServerlessSpec
import uuid
import requests
from bs4 import BeautifulSoup
from readability import Document

# Load .env
load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env")
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()

# LLM setup (Groq/OpenAI-compatible)
llm = ChatOpenAI(
    model=os.getenv("MODEL", "meta-llama/llama-4-scout-17b-16e-instruct"),
    openai_api_base=os.getenv("BASE_URL", "https://api.groq.com/openai/v1"),
    openai_api_key=os.getenv("API_KEY"),  
    temperature=float(os.getenv("TEMPERATURE", "0.6")),
)

# Google Search setup
google_api_wrapper = GoogleSearchAPIWrapper(
    google_api_key=os.getenv("GOOGLE_API_KEY"),
    google_cse_id=os.getenv("GOOGLE_CSE_ID"),
    k=5
)

# Pinecone setup
pinecone_api_key = os.environ['PINECONE_API_KEY']
pinecone_index_name = os.environ.get('PINECONE_INDEX', 'pinecone')
pc = Pinecone(api_key=pinecone_api_key)
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
dimension = 384
spec = ServerlessSpec(cloud='aws', region='us-east-1')
existing_indexes = [index_info["name"] for index_info in pc.list_indexes()]
if pinecone_index_name not in existing_indexes:
    pc.create_index(
        name=pinecone_index_name,
        dimension=dimension,
        metric='cosine',
        spec=spec)
index = pc.Index(pinecone_index_name)

# --- Pinecone memory functions ---
def store_user_memory(user_id, text, conversation_id=None, conversation_title=None, mem_type="note", is_factual=False, importance=0.5, topic="general"):
    """
    Store user memory with enhanced metadata for cross-conversation retrieval
    """
    embedding_vector = embedding_model.encode([text])[0].tolist()
    unique_id = str(uuid.uuid4())
    metadata = {
        "user_id": user_id,
        "text": text,
        "timestamp": int(time.time()),
        "type": mem_type,
        "conversation_id": conversation_id or "",
        "conversation_title": conversation_title or "",
        "is_factual": is_factual,
        "importance": importance,
        "topic": topic
    }
    index.upsert(vectors=[(unique_id, embedding_vector, metadata)])
    return True

def retrieve_user_memories(user_id, query, conversation_id=None, top_k=3):
    """
    Retrieve memories with support for cross-conversation retrieval
    
    Returns:
        dict: Dictionary with 'current' and 'other' conversation memories
    """
    embedding_vector = embedding_model.encode([query])[0].tolist()
    
    # Get memories from current conversation
    current_filter = {"user_id": user_id}
    if conversation_id:
        current_filter["conversation_id"] = conversation_id
        
    current_results = index.query(
        vector=embedding_vector,
        top_k=top_k,
        include_metadata=True,
        filter=current_filter
    )
    
    # Format results
    memories = {
        "current": [],
        "other": []
    }
    
    for match in current_results['matches']:
        metadata = match.get('metadata', {})
        memories["current"].append({
            "text": metadata.get('text', ''),
            "role": metadata.get('type', 'user'),
            "timestamp": metadata.get('timestamp', 0),
            "conversation_id": metadata.get('conversation_id', ''),
            "similarity": match.get('score', 0),
            "is_factual": metadata.get('is_factual', False)
        })
    
    # Get cross-conversation memories if conversation_id is provided
    if conversation_id:
        cross_results = index.query(
            vector=embedding_vector,
            top_k=top_k,
            include_metadata=True,
            filter={
                "user_id": user_id,
                "$or": [
                    {"is_factual": True},
                    {"importance": {"$gte": 0.7}}
                ]
            },
            filter_not={"conversation_id": conversation_id}
        )
        
        for match in cross_results['matches']:
            metadata = match.get('metadata', {})
            memories["other"].append({
                "text": metadata.get('text', ''),
                "role": metadata.get('type', 'user'),
                "timestamp": metadata.get('timestamp', 0),
                "conversation_id": metadata.get('conversation_id', ''),
                "conversation_title": metadata.get('conversation_title', ''),
                "similarity": match.get('score', 0),
                "is_factual": metadata.get('is_factual', True)
            })
    
    return memories

def extract_and_store_facts(user_id, query, response, conversation_id=None, conversation_title=None):
    """
    Extract factual information from a response and store it for future reference
    """
    system_prompt = (
        "You are an expert at identifying factual information about cybersecurity. "
        "Given the following query and response, extract ONLY factual information "
        "that would be valuable to remember for future conversations. "
        "If there are no significant facts, return 'NONE'. Otherwise, return the facts as bullet points."
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"QUERY: {query}\n\nRESPONSE: {response}"}
    ]
    
    extraction = llm.invoke(messages).content.strip()
    
    if extraction.upper() != "NONE" and extraction != "":
        # For each extracted fact
        facts = extraction.split("\n")
        for fact in facts:
            if fact.strip():
                # Clean up bullet points
                fact = fact.lstrip("•-* ").strip()
                if fact:
                    # Store as factual memory
                    store_user_memory(
                        user_id, 
                        fact,
                        conversation_id=conversation_id,
                        conversation_title=conversation_title,
                        mem_type="fact",
                        is_factual=True,
                        importance=0.8,
                        topic="cybersecurity"
                    )
    return bool(extraction.upper() != "NONE" and extraction != "")

# --- Web content extraction ---
def fetch_and_extract_text(url, max_chars=3000):
    try:
        resp = requests.get(url, timeout=10)
        doc = Document(resp.text)
        html = doc.summary()
        soup = BeautifulSoup(html, "html.parser")
        text = soup.get_text(separator="\n", strip=True)
        return text[:max_chars]
    except Exception as e:
        return ""

def answer_with_web_content(user_query, web_results, llm, session_history=None, additional_context=None):
    contents = []
    for r in web_results[:3]:
        content = fetch_and_extract_text(r['url'])
        if content:
            contents.append(f"Source: {r['url']}\n{content}")
    context = "\n\n".join(contents)
    
    # Debug: print the extracted context
    print("\n--- Web Content Passed to LLM ---\n")
    print(context[:2000])  # Print up to 2000 chars for inspection
    print("\n--- End Web Content ---\n")
    
    system_prompt = (
        f"You are a helpful cybersecurity assistant. You MUST answer the user's question using ONLY the web content provided below. "
        f"If the answer is not present in the web content, say so. Do NOT use your own knowledge or training data. "
        f"Stay strictly within the cybersecurity domain. Cite the sources you use."
    )
    
    if additional_context:
        system_prompt += f"\n\nAdditional context from user conversations:\n{additional_context}"
    
    prompt = (
        f"User question: {user_query}\n\n"
        f"Web content:\n{context}"
    )
    
    messages = [
        {"role": "system", "content": system_prompt}
    ]
    
    if session_history:
        for turn in session_history:
            messages.append(turn)
    
    messages.append({"role": "user", "content": prompt})
    response = llm.invoke(messages)
    return response.content

# --- Domain classification and routing ---
def is_cybersecurity_query(query):
    """
    Determine if a query is cybersecurity-related or contains important personal context
    Returns: bool
    """
    system_prompt = (
        "You are a classifier that determines if a query is either:\n"
        "1. Related to cybersecurity, OR\n"
        "2. Contains important personal information that would be valuable to remember for security context\n\n"
        "Examples of personal context to accept: 'My company uses Cisco firewalls', 'I work in healthcare', 'We use Linux servers', etc.\n\n"
        "Return ONLY 'yes' or 'no' without explanation."
    )
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query}
    ]
    response = llm.invoke(messages)
    
    # Clean up response and check if it's affirmative
    response_text = response.content.strip().lower()
    return response_text.startswith("yes")

def is_personal_fact(text):
    """
    Determine if text contains personal factual information worth remembering
    Returns: bool, str (reason)
    """
    system_prompt = (
        "You analyze text to determine if it contains personal information worth remembering for a security context.\n"
        "Examples: system configurations, security tools used, industries, work environments, software versions.\n"
        "If it DOES contain important personal context, respond with 'YES: <the factual information>'.\n"
        "If it does NOT contain important personal context, respond with 'NO'.\n"
    )
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": text}
    ]
    
    response = llm.invoke(messages)
    response_text = response.content.strip()
    
    if response_text.lower().startswith("yes:"):
        # Extract the personal fact from the response
        fact = response_text[4:].strip()
        return True, fact
    else:
        return False, ""

# --- LLM logic ---
def needs_web_search(user_query, context=None):
    """
    Determine if a web search is needed for the query
    
    Args:
        user_query: The user's question
        context: Optional context from user memories
        
    Returns:
        bool: True if web search is needed, False otherwise
    """
    system_prompt = (
        "You are an expert assistant. For the following user question, answer only with 'yes' if you need to search the web to provide an accurate, up-to-date answer. "
        "If you can answer confidently from your own knowledge, answer only with 'no'."
    )
    
    if context:
        system_prompt += f"\n\nHere is some relevant context from the user's previous conversations:\n{context}"
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_query}
    ]
    response = llm.invoke(messages)
    return response.content.strip().lower().startswith("yes")

# Alias for external use (identical functionality but easier to understand the intent)
def should_use_web_search(user_query, context=None):
    """
    Determine if a web search should be used for this query.
    This is an alias of needs_web_search for external imports.
    
    Args:
        user_query: The user's question
        context: Optional context from user memories
        
    Returns:
        bool: True if web search should be used, False otherwise
    """
    return needs_web_search(user_query, context)

def query_llm(user_query, user_memories=None, session_history=None):
    system_prompt = (
        "You are a cybersecurity expert assistant. Provide clear, accurate, and up-to-date answers about cybersecurity concepts, threats, best practices, and incident response. "
        "If the user has provided personal or contextual information, use it to personalize your answer. "
        "If you are unsure or need more information, say 'I don't know' and suggest searching the web for the latest data."
    )
    context = ""
    if user_memories:
        context = "\n\nUser memory/context (for personalization):\n" + "\n".join(f"- {m}" for m in user_memories)
    messages = [
        {"role": "system", "content": system_prompt + context}
    ]
    # Add session history if provided
    if session_history:
        for turn in session_history:
            messages.append(turn)
    messages.append({"role": "user", "content": user_query})
    response = llm.invoke(messages)
    return response.content

def google_search(query, max_results=5):
    results = google_api_wrapper.results(query, num_results=max_results)
    return [
        {"title": r["title"], "url": r["link"], "snippet": r.get("snippet", "")} for r in results
    ]

def format_answer(llm_answer, web_results=None):
    if web_results:
        sources = "\n".join([f"- [{r['title']}]({r['url']})" for r in web_results])
        return f"{llm_answer}\n\n**Sources:**\n{sources}"
    return llm_answer

def answer_cybersec_query(user_query, user_id, session_history=None, conversation_id=None, conversation_title=None, force_web_search=False):
    """
    Enhanced version that answers a cybersecurity query with better formatting, web search control,
    conversation context awareness, and cross-conversation memory.
    
    Args:
        user_query: The user's cybersecurity question
        user_id: The user's ID for retrieving memories
        session_history: List of previous conversation turns for context
        conversation_id: ID of the current conversation (for context)
        conversation_title: Title of the current conversation
        force_web_search: If True, always use web search regardless of query
    
    Returns:
        Dict containing the answer, links, and web search status
    """
    # First, determine if this contains personal facts worth remembering
    contains_fact, extracted_fact = is_personal_fact(user_query)
    
    # If it contains a personal fact, store it automatically
    if contains_fact:
        store_user_memory(
            user_id, 
            extracted_fact,
            conversation_id=conversation_id,
            conversation_title=conversation_title,
            mem_type="fact",
            is_factual=True,
            importance=0.8,
            topic="cybersecurity"
        )
    
    # Then, check if it's a cybersecurity query (this check is now more lenient)
    if not is_cybersecurity_query(user_query):
        if contains_fact:
            # If it contains a fact but isn't a cybersecurity query, acknowledge the fact but redirect
            return {
                "answer": f"I've noted that {extracted_fact}. How can I help you with any cybersecurity questions related to this?",
                "is_cybersec": True,  # Mark as true to keep the conversation going
                "stored_facts": True
            }
        else:
            # If it's completely off-topic with no personal facts, decline politely
            return {
                "answer": "I can only help with cybersecurity topics. Please ask something related to web security, hacking, threats, or protection.",
                "is_cybersec": False
            }
    
    # Retrieve user memories for context
    user_memories = retrieve_user_memories(user_id, user_query, conversation_id, top_k=5)
    
    # Format memory context
    memory_context = ""
    if user_memories["current"]:
        memory_context += "\n\nCurrent conversation context:\n" + "\n".join(
            f"- {mem['role'].upper()}: {mem['text']}" for mem in user_memories["current"]
        )
    
    # Format cross-conversation context
    cross_context = ""
    if user_memories["other"]:
        cross_context += "\n\nIMPORTANT CONTEXT FROM OTHER CONVERSATIONS:\n" + "\n".join(
            f"- From '{mem.get('conversation_title', 'Previous conversation')}': {mem['text']}" 
            for mem in user_memories["other"]
        )
    
    # Prepare context from session history
    session_context = ""
    if session_history:
        session_context = "\n\nPrevious conversation context:\n"
        for turn in session_history:
            role = turn["role"]
            content = turn["content"]
            session_context += f"{role.upper()}: {content}\n"
        session_context += "\nUse the above conversation context to understand references like 'this vulnerability' or 'it' in the current question.\n"
    
    # Combine all context
    combined_context = memory_context + cross_context + session_context
    
    # If we just stored a fact, add it to the context
    if contains_fact:
        combined_context += f"\n\nIMPORTANT: The user just shared this personal information: {extracted_fact}\n"
    
    # Decide if web search is needed (override with force_web_search)
    should_search = force_web_search or needs_web_search(user_query, combined_context)
    
    # If web search is needed, perform it
    if should_search:
        web_results = google_search(user_query)
        web_content_answer = answer_with_web_content(
            user_query, 
            web_results, 
            llm, 
            session_history=session_history,
            additional_context=combined_context
        )
        
        # Extract and store factual information from the response
        extracted_facts = extract_and_store_facts(
            user_id, 
            user_query, 
            web_content_answer, 
            conversation_id, 
            conversation_title
        )
        
        return {
            "answer": format_answer(web_content_answer, web_results),
            "used_web_search": True,
            "is_cybersec": True,
            "stored_facts": extracted_facts or contains_fact
        }
    
    # For non-web-search queries, use LLM with context
    system_prompt = (
        "You are a cybersecurity expert assistant. Provide clear, accurate, and up-to-date answers about cybersecurity concepts, threats, best practices, and incident response. "
        "Your primary focus is cybersecurity, but if the user shares personal context about their systems or environment, acknowledge it and use it to personalize your answers. "
        "If the user has provided personal or contextual information, always use it to personalize your answer. "
        "If you are unsure or need more information, say 'I don't know' and suggest searching the web for the latest data."
    )
    
    # Add context from session history and user memories
    if combined_context:
        system_prompt += combined_context
    
    messages = [
        {"role": "system", "content": system_prompt}
    ]
    
    # Add session history if provided
    if session_history:
        for turn in session_history:
            messages.append(turn)
    
    messages.append({"role": "user", "content": user_query})
    response = llm.invoke(messages)
    
    # Extract and store factual information from the response
    extracted_facts = extract_and_store_facts(
        user_id, 
        user_query, 
        response.content, 
        conversation_id, 
        conversation_title
    )
    
    return {
        "answer": format_answer(response.content),
        "used_web_search": False,
        "is_cybersec": True,
        "stored_facts": extracted_facts or contains_fact
    }

# Flask app for API endpoint
app = Flask(__name__)

@app.route('/ask', methods=['POST'])
def ask():
    data = request.json
    user_query = data.get('question')
    user_id = data.get('user_id')
    session_history = data.get('session_history')  # Optional: list of previous turns
    conversation_id = data.get('conversation_id')  # Optional: for conversation context
    conversation_title = data.get('conversation_title')  # Optional: for better memory context
    
    if not user_query or not user_id:
        return jsonify({"error": "Both 'question' and 'user_id' are required."}), 400
    
    result = answer_cybersec_query(
        user_query, 
        user_id, 
        session_history=session_history,
        conversation_id=conversation_id,
        conversation_title=conversation_title
    )
    
    return jsonify(result)

@app.route('/remember', methods=['POST'])
def remember():
    data = request.json
    user_id = data.get('user_id')
    text = data.get('text')
    mem_type = data.get('type', 'note')
    conversation_id = data.get('conversation_id')
    conversation_title = data.get('conversation_title')
    is_factual = data.get('is_factual', False)
    importance = data.get('importance', 0.5)
    topic = data.get('topic', 'general')
    
    if not user_id or not text:
        return jsonify({"error": "Both 'user_id' and 'text' are required."}), 400
    
    store_user_memory(
        user_id, 
        text, 
        conversation_id=conversation_id,
        conversation_title=conversation_title,
        mem_type=mem_type,
        is_factual=is_factual,
        importance=importance,
        topic=topic
    )
    
    return jsonify({"message": "Memory stored successfully."})

# Example usage:
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'serve':
        app.run(port=1500)
    else:
        user_id = input("Enter your user_id: ")
        q = input("Ask a question: ")
        print(answer_cybersec_query(q, user_id)["answer"])
                

