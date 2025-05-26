"""
Cybersecurity query handler module.
This module provides functions for handling cybersecurity queries with cross-conversation memory.
"""

import os
from datetime import datetime
from bson import ObjectId
from cybersec import answer_cybersec_query as cybersec_answer

def get_conversation_context(user, conversation_id, user_query):
    """
    Extract conversation context for a cybersecurity query.
    
    Args:
        user: User document from MongoDB
        conversation_id: ID of the current conversation
        user_query: Current user query
        
    Returns:
        tuple: (conversation, conversation_title, session_history)
    """
    conversations = user.get('conversations', [])
    conversation = next((conv for conv in conversations if conv["id"] == conversation_id), None)
    
    if not conversation:
        return None, None, []
        
    # Get ALL messages for better context
    messages = conversation.get('messages', [])
    conversation_title = conversation.get('title', 'Untitled Conversation')
    
    # If there are too many messages, get a subset focused on the most recent ones
    if len(messages) > 15:
        session_history = [
            {"role": msg["role"], "content": msg["content"]}
            for msg in messages[-15:]  # Get the last 15 messages
        ]
    else:
        session_history = [
            {"role": msg["role"], "content": msg["content"]}
            for msg in messages
        ]
    
    # Add the current query to the conversation
    current_time = datetime.utcnow().isoformat() + "Z"
    user_message = {"role": "user", "content": user_query, "timestamp": current_time}
    messages.append(user_message)
    conversation["messages"] = messages
    conversation["updated_at"] = current_time
    
    # Update conversation in database
    for i, conv in enumerate(conversations):
        if conv["id"] == conversation_id:
            conversations[i] = conversation
            break
            
    return conversation, conversation_title, session_history

def answer_query(user_query, user_id, session_history=None, conversation_id=None, conversation_title=None, force_web_search=False):
    """
    Answer a cybersecurity query with cross-conversation memory integration.
    
    Args:
        user_query: The user's cybersecurity question
        user_id: The user's ID for retrieving memories
        session_history: List of previous conversation turns for context
        conversation_id: ID of the current conversation
        conversation_title: Title of the current conversation
        force_web_search: If True, always use web search regardless of query
        
    Returns:
        dict: Response containing answer, web search status, etc.
    """
    # Get answer from the cybersecurity module
    result = cybersec_answer(
        user_query, 
        user_id, 
        session_history=session_history,
        conversation_id=conversation_id,
        conversation_title=conversation_title,
        force_web_search=force_web_search
    )
    
    # Log non-cybersecurity queries for monitoring
    if result.get("is_cybersec") is False:
        print(f"Non-cybersecurity query detected: '{user_query}'")
        
    return result

def update_conversation_with_response(user_id, conversation, answer, users_collection, reply_to=None):
    """
    Update a conversation with the assistant's response.
    
    Args:
        user_id: User ID
        conversation: Conversation document
        answer: Assistant's answer to add
        users_collection: MongoDB users collection
        reply_to: Optional reply reference
        
    Returns:
        bool: Success status
    """
    messages = conversation.get("messages", [])
    conversations = None
    
    # Add the assistant response
    assistant_message = {
        "role": "assistant",
        "content": answer,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    # Add reply_to if provided
    if reply_to:
        assistant_message["replyTo"] = reply_to
    
    messages.append(assistant_message)
    conversation["messages"] = messages
    conversation["updated_at"] = assistant_message["timestamp"]
    
    # Find the conversation in the user's conversations array and update it
    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if user:
        conversations = user.get('conversations', [])
        for i, conv in enumerate(conversations):
            if conv["id"] == conversation["id"]:
                conversations[i] = conversation
                break
                
        users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"conversations": conversations}}
        )
        return True
        
    return False 