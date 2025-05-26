import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import ReactMarkdown from 'react-markdown';
import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import Sidebar from './Sidebar';
import { docco } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import { FaPaperclip, FaHistory } from 'react-icons/fa';
import { FiArrowUp, FiGlobe, FiFile } from 'react-icons/fi';

const Chat = () => {
  const { conversationId } = useParams();
  const [message, setMessage] = useState('');
  const [conversations, setConversations] = useState([]);
  const [currentConversation, setCurrentConversation] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const messageEndRef = useRef(null);
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [messages, setMessages] = useState([]);
  const [streamingResponse, setStreamingResponse] = useState('');
  const messageRefs = useRef([]);
  const [webSearchEnabled, setWebSearchEnabled] = useState(false);
  const [autoSearchActive, setAutoSearchActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState('');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedFileDisplay, setUploadedFileDisplay] = useState(null);
  const [editingMsgIdx, setEditingMsgIdx] = useState(null);
  const [editingMsgValue, setEditingMsgValue] = useState('');
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState('');
  const [pairVersionIdx, setPairVersionIdx] = useState({}); // {userMsgIndex: versionIndex}
  const fileInputRef = useRef(null);
  const [replyTo, setReplyTo] = useState(null);
  const [fileLocked, setFileLocked] = useState(false);
  // Track which message has a file attached to it
  const [fileAttachedToMessageIdx, setFileAttachedToMessageIdx] = useState(null);
  const [conversationsLoaded, setConversationsLoaded] = useState(false);
  const [retryCount, setRetryCount] = useState(0);
  const [showFileSelector, setShowFileSelector] = useState(false);
  const [previousFiles, setPreviousFiles] = useState([]);
  const [loadingPreviousFiles, setLoadingPreviousFiles] = useState(false);

  // Define functions that need to be used by other functions
  const handleNewChat = async () => {
    try {
      const response = await axios.post('/conversations/new', {});
      const newConversation = response.data.conversation;
      setConversations(prev => sortConversations([newConversation, ...prev]));
      navigate(`/chat/${newConversation.id}`);
    } catch {
      // Suppress error
    }
  };

  const handleDeleteConversation = async (id) => {
    try {
      await axios.delete(`/conversations/${id}`);
      setConversations(prev => sortConversations(prev.filter(conv => conv.id !== id)));
      if (id === conversationId) {
        if (conversations.length > 1) {
          // Find the next conversation to navigate to
          const nextConv = conversations.find(conv => conv.id !== id);
          if (nextConv) {
            navigate(`/chat/${nextConv.id}`);
          }
        } else {
          // Create a new conversation if this was the last one
          handleNewChat();
        }
      }
    } catch {
      // Suppress error
    }
  };

  const handleRenameConversation = async (id, newTitle) => {
    try {
      await axios.put(`/conversations/${id}/rename`, { title: newTitle });
      setConversations(prev => sortConversations(
        prev.map(conv =>
          conv.id === id ? { ...conv, title: newTitle } : conv
        )
      ));
      if (id === conversationId && currentConversation) {
        setCurrentConversation({ ...currentConversation, title: newTitle });
      }
      return {}; // Success
    } catch (error) {
      const msg = extractRenameError(error) || '';
      if (msg) {
        return { error: msg };
      }
      return {};
    }
  };

  const handleLogout = () => {
    logout();
    setConversations([]);
    setMessages([]);
    setCurrentConversation(null);
    navigate('/login');
  };

  // Function to fetch the latest conversation data
  const fetchConversation = async () => {
    if (!conversationId) return;
    
    try {
      const token = localStorage.getItem('token');
      const response = await axios.get(`/conversations/${conversationId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data && response.data.conversation) {
        // Just use the conversation data as-is
        const conv = response.data.conversation;
        setMessages(conv.messages || []);
        setCurrentConversation(conv);
        
        // Update this conversation in the conversations list
        setConversations(prevConvs => {
          return sortConversations(prevConvs.map(c => 
            c.id === conv.id ? {
              ...c, 
              title: conv.title,
              updated_at: conv.updated_at,
              message_count: (conv.messages || []).length
            } : c
          ));
        });
      }
    } catch (error) {
      console.error('Error fetching conversation:', error);
    }
  };

  // Utility: Only show error for duplicate conversation names
  const extractRenameError = (error) => {
    if (
      error?.response?.data?.msg &&
      error.response.data.msg.toLowerCase().includes('already exists')
    ) {
      return error.response.data.msg;
    }
    return '';
  };

  // Utility function to sort conversations newest to oldest
  const sortConversations = (convs) => {
    return [...convs].sort((a, b) => {
      const aTime = new Date(a.updated_at || a.created_at).getTime();
      const bTime = new Date(b.updated_at || b.created_at).getTime();
      return bTime - aTime;
    });
  };

  // Utility function for truncating reply context
  const getReplyPreview = (content, maxLen = 80) => {
    if (!content) return '';
    const singleLine = content.replace(/\s+/g, ' ').trim();
    return singleLine.length > maxLen ? singleLine.slice(0, maxLen) + '...' : singleLine;
  };

  // Fetch all conversations on mount and after relevant actions
  const fetchConversations = useCallback(async () => {
    try {
      console.log("Fetching conversations...");
      setIsLoading(true);
      const response = await axios.get('/conversations');
      const convs = response.data.conversations || [];
      console.log(`Loaded ${convs.length} conversations`);
      
      if (convs.length > 0) {
        setConversations(sortConversations(convs));
        setConversationsLoaded(true);
        setRetryCount(0); // Reset retry count on successful load
      } else if (retryCount < 3) {
        // If no conversations were loaded and we haven't hit retry limit
        console.log(`No conversations loaded, retrying (${retryCount + 1}/3)...`);
        setTimeout(() => {
          setRetryCount(prev => prev + 1);
        }, 500); // Retry after 500ms
      }
    } catch (err) {
      console.error("Error fetching conversations:", err);
      if (retryCount < 3) {
        // Retry on errors too
        console.log(`Error loading conversations, retrying (${retryCount + 1}/3)...`);
        setTimeout(() => {
          setRetryCount(prev => prev + 1);
        }, 500); // Retry after 500ms
      }
    } finally {
      setIsLoading(false);
    }
  }, [retryCount]);

  useEffect(() => {
    fetchConversations();
  }, [fetchConversations]);

  // Retry mechanism
  useEffect(() => {
    if (retryCount > 0 && retryCount <= 3) {
      fetchConversations();
    }
  }, [retryCount, fetchConversations]);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    messageEndRef.current?.scrollIntoView();
  }, [currentConversation?.messages]);

  useEffect(() => {
    scrollToBottom();
  }, [messages, streamingResponse]);

  const scrollToBottom = () => {
    messageEndRef.current?.scrollIntoView();
  };

  // Scroll to a specific message index if requested
  useEffect(() => {
    if (window.location.hash.startsWith('#msg-')) {
      const idx = parseInt(window.location.hash.replace('#msg-', ''), 10);
      if (!isNaN(idx) && messageRefs.current[idx]) {
        messageRefs.current[idx].scrollIntoView({ behavior: 'smooth', block: 'center' });
        messageRefs.current[idx].classList.add('ring-2', 'ring-yellow-400');
        setTimeout(() => {
          messageRefs.current[idx]?.classList.remove('ring-2', 'ring-yellow-400');
        }, 2000);
      }
    }
  }, [messages]);

  // Streaming send message
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!message.trim() || !conversationId) return;
    setIsLoading(true);
    setError('');
    let reply = '';
    try {
      const token = localStorage.getItem('token');
      const response = await fetch(`/chat/${conversationId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ message })
      });
      if (!response.body) throw new Error('No response body');
      const reader = response.body.getReader();
      setCurrentConversation((prev) => {
        if (!prev) return prev;
        // Only add a user message and a blank assistant message if the last message isn't already the same
        const lastMsg = prev.messages[prev.messages.length - 1];
        if (!lastMsg || lastMsg.role !== 'user' || lastMsg.content !== message) {
          return { ...prev, messages: [...prev.messages, { role: 'user', content: message }, { role: 'assistant', content: '' }] };
        }
        return prev;
      });
      let isFirstChunk = true;
      let partial = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = new TextDecoder().decode(value);
        // Filter out any JSON-looking reply (old non-streaming reply)
        if (isFirstChunk && chunk.trim().startsWith('{')) {
          setError('Received a non-streaming JSON reply. Please try again.');
          break;
        }
        isFirstChunk = false;
        partial += chunk;
        reply = partial;
        setCurrentConversation((prev) => {
          if (!prev) return prev;
          const updatedMessages = [...prev.messages];
          // Update the last assistant message
          if (updatedMessages.length && updatedMessages[updatedMessages.length - 1].role === 'assistant') {
            updatedMessages[updatedMessages.length - 1] = { role: 'assistant', content: partial };
          }
          return { ...prev, messages: updatedMessages };
        });
      }
      setMessage('');
      // Optionally, update conversations list (fetch again or update state)
    } catch (error) {
      console.error('Error sending message:', error);
      setError('Failed to send message');
    } finally {
      setIsLoading(false);
    }
  };

  // Modified submit handler to track file attachment
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!message.trim() || !conversationId) return;
    
    // Reset auto search indicator
    setAutoSearchActive(false);
    setReplyTo(null);

    // Build the user message
    const userMessage = {
      role: 'user',
      content: message,
    };

    // Add reply context if available
    if (replyTo && replyTo.msg) {
      userMessage.replyTo = { 
        index: replyTo.index, 
        content: replyTo.msg.content 
      };
    }

    // Add file information if available
    const fileId = uploadedFile?.file_id || null;
    if (uploadedFileDisplay && fileId) {
      userMessage.hasFile = true;
      userMessage.fileName = uploadedFileDisplay;
      userMessage.file_id = fileId;
    }
    
    // Immediately update local state with file information
    const newMessageIndex = messages.length;
    setMessages(prevMessages => [...prevMessages, userMessage]);
    setMessage('');
    setIsLoading(true);
    setStreamingResponse('');
    
    try {
      // Send the message to the server
      const token = localStorage.getItem('token');
      
      // Determine which endpoint to use based on webSearchEnabled
      const endpoint = webSearchEnabled 
        ? `/conversations/${conversationId}/web_search` 
        : `/chat/${conversationId}`;
      
      const payloadData = {
        message,
        force_web_search: false,
        replyTo: replyTo?.msg ? { 
          index: replyTo.index, 
          content: replyTo.msg.content,
          isCurrentVersion: true
        } : undefined,
        file_id: fileId // Send file_id to the server
      };

      console.log('Sending message with payload:', payloadData);
      
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(payloadData)
      });

      if (!response.body) throw new Error('No response body');
      const reader = response.body.getReader();
      let partial = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = new TextDecoder().decode(value);
        partial += chunk;
        setStreamingResponse(partial);
      }
      setStreamingResponse('');
      
      // Check if web search was used
      const wasWebSearchUsed = webSearchEnabled || response.headers.get('X-Web-Search-Used') === 'true';
      if (wasWebSearchUsed) {
        setAutoSearchActive(true);
      }
      
      // Fetch updated conversation
      await fetchConversation();
      
      // Reset web search mode after sending
      setWebSearchEnabled(false);
      
      // Clear uploaded file after sending
      setUploadedFile(null);
      setUploadedFileDisplay(null);
      setFileLocked(false);
      
    } catch (error) {
      console.error('Error sending message:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // Update the file upload handler
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !conversationId) return;
    
    console.log(`Uploading file ${file.name} for conversation ${conversationId}`);
    setUploading(true);
    setUploadStatus('');
    
    try {
      const token = localStorage.getItem('token');
      const formData = new FormData();
      formData.append('file', file);
      formData.append('conversation_id', conversationId); // Add conversation ID to the upload
      
      const response = await axios.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data', Authorization: `Bearer ${token}` },
      });
      
      console.log('File upload response:', response.data);
      
      // Set uploaded file data with file_id from response
      const fileObj = {
        file_id: response.data.file_id,
        name: file.name,
        display_name: response.data.filename || file.name
      };
      
      setUploadedFile(fileObj);
      setUploadedFileDisplay(response.data.filename || file.name);
      setUploadStatus(response.data.msg);
      setFileLocked(false); // Ensure the file can be removed
      
      console.log(`File uploaded with ID: ${fileObj.file_id}`);
    } catch (err) {
      console.error('Upload error:', err);
      setUploadStatus('Upload failed: ' + (err.response?.data?.msg || err.message));
      setUploadedFile(null);
      setUploadedFileDisplay(null);
    } finally {
      setUploading(false);
    }
  };

  const clearUploadedFile = () => {
    setUploadedFile(null);
    setUploadedFileDisplay(null);
    setUploadStatus('');
    setFileLocked(false);
  };

  // Custom renderer for code blocks in markdown
  const components = {
    code({ node, inline, className, children, ...props }) {
      const match = /language-(\w+)/.exec(className || '');
      return !inline && match ? (
        <SyntaxHighlighter
          style={oneDark}
          language={match[1]}
          PreTag="div"
          {...props}
        >
          {String(children).replace(/\n$/, '')}
        </SyntaxHighlighter>
      ) : (
        <code className={className} {...props}>
          {children}
        </code>
      );
    },
    // Add custom renderers for links and paragraphs
    a({ node, children, href, ...props }) {
      // Check if this is a source link by looking at the text content
      const isSourceLink = React.Children.toArray(children).some(child => {
        if (typeof child === 'string') {
          return child.match(/^\[\d+\]/);
        }
        return false;
      });
      
      return (
        <a 
          href={href} 
          target="_blank" 
          rel="noopener noreferrer" 
          className={isSourceLink 
            ? "text-blue-600 hover:underline font-bold text-lg block my-3 py-2" 
            : "text-blue-600 hover:underline"}
          {...props}
        >
          {children}
        </a>
      );
    },
    // Custom renderer for paragraphs to handle source lists
    p({ node, children, ...props }) {
      // Check if this paragraph contains "Sources:" text
      const childrenArray = React.Children.toArray(children);
      const text = childrenArray.map(child => 
        typeof child === 'string' ? child : ''
      ).join('');
      
      if (text.includes('Sources:')) {
        // This is a sources paragraph, let's format it specially
        const sourcesIndex = text.indexOf('Sources:');
        const beforeSources = text.substring(0, sourcesIndex + 8); // +8 for "Sources:"
        
        // We now get the rest of the children, which should include Markdown links
        // that will be processed by the ReactMarkdown 'a' renderer
        const sourcesContent = childrenArray.map(child => {
          if (typeof child === 'string') {
            // Only process the part after "Sources:"
            if (child.includes('Sources:')) {
              return child.substring(child.indexOf('Sources:') + 8);
            }
          }
          return child;
        });
        
        return (
          <div className="sources-section mt-3">
            <p className="font-semibold">{beforeSources}</p>
            <div className="mt-4 space-y-6">
              {sourcesContent}
            </div>
          </div>
        );
      }
      
      return <p {...props}>{children}</p>;
    }
  };

  // Edit submit handler (calls backend)
  const handleEditSubmit = async (index) => {
    if (!editingMsgValue.trim()) return;
    setEditLoading(true);
    setEditError('');
    try {
      const token = localStorage.getItem('token');
      const response = await axios.put(
        `/conversations/${conversationId}/messages/${index}/edit`,
        { content: editingMsgValue },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      if (response.data && response.data.conversation) {
        setCurrentConversation(response.data.conversation);
        setMessages(response.data.conversation.messages || []);
        setEditingMsgIdx(null);
        setEditingMsgValue('');
        setPairVersionIdx({});
      }
    } catch (err) {
      setEditError(err?.response?.data?.msg || 'Failed to edit message');
    } finally {
      setEditLoading(false);
    }
  };

  // Version toggle handler for user+assistant pair
  const handlePairVersionToggle = (userMsgIdx, direction) => {
    setPairVersionIdx(prev => {
      const msg = messages[userMsgIdx];
      const assistantMsg = messages[userMsgIdx + 1];
      const versions = msg && msg.versions ? msg.versions.length : 0;
      let current = prev[userMsgIdx] || 0;
      let next = current + direction;
      if (next < 0) next = 0;
      if (versions && next > versions) next = versions;
      return { ...prev, [userMsgIdx]: next };
    });
  };

  // Helper to get the displayed content for a user+assistant pair version
  const getPairDisplayedContent = (msg, idx, isAssistant) => {
    const vIdx = pairVersionIdx[idx] || 0;
    if (msg.versions && msg.versions.length && vIdx > 0) {
      // Most recent version is at the end
      const version = msg.versions[msg.versions.length - vIdx];
      return version ? version.content : msg.content;
    }
    return msg.content;
  };

  // Modified message input handler for textarea
  const handleInputKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  // Restore and update the fetch conversation effect for when conversationId changes
  useEffect(() => {
    if (!conversationId) return;
    setMessages([]);
    setCurrentConversation(null);
    
    const fetchCurrentConversation = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`/conversations/${conversationId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        
        if (response.data && response.data.conversation) {
          const conv = response.data.conversation;
          setMessages(conv.messages || []);
          setCurrentConversation(conv);
          
          setConversations(prevConvs => sortConversations(prevConvs.map(c =>
            c.id === conv.id ? {
              ...c,
              title: conv.title,
              updated_at: conv.updated_at,
              message_count: (conv.messages || []).length
            } : c
          )));
        }
      } catch (error) {
        console.error('Error fetching conversation:', error);
      }
    };
    
    fetchCurrentConversation();
  }, [conversationId]);

  // Restore the effect for ensuring new users have a conversation
  useEffect(() => {
    const createNewConversationIfNeeded = async () => {
      if (!conversationId && conversations.length === 0) {
        try {
          const response = await axios.post('/conversations/new', {});
          const newConversation = response.data.conversation;
          setConversations(sortConversations([newConversation]));
          navigate(`/chat/${newConversation.id}`);
        } catch {
          // Suppress error
        }
      } else if (!conversationId && conversations.length > 0) {
        navigate(`/chat/${conversations[0].id}`);
      }
    };
    
    createNewConversationIfNeeded();
  }, [conversationId, conversations, navigate]);

  // Add function to fetch previously uploaded files
  const fetchPreviousFiles = useCallback(async () => {
    try {
      setLoadingPreviousFiles(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('/user/files', {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.data && response.data.files) {
        setPreviousFiles(response.data.files);
      }
    } catch (error) {
      console.error('Error fetching previous files:', error);
    } finally {
      setLoadingPreviousFiles(false);
    }
  }, []);

  // Update the select previous file function to provide better feedback
  const selectPreviousFile = async (fileId, fileName) => {
    try {
      console.log(`Selecting previous file: ${fileName} (${fileId})`);
      setUploading(true);
      setUploadStatus('Loading previously uploaded file...');
      
      const token = localStorage.getItem('token');
      const response = await axios.get(`/file/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data) {
        console.log('File content retrieved:', {
          fileId: response.data.file_id,
          fileName: response.data.filename,
          contentLength: response.data.content?.length,
          metadata: response.data.metadata
        });
        
        const fileObj = {
          file_id: fileId,
          name: fileName,
          display_name: fileName
        };
        
        setUploadedFile(fileObj);
        setUploadedFileDisplay(fileName);
        setUploadStatus('File selected successfully');
        console.log(`Previous file selected with ID: ${fileId}`);
      }
    } catch (error) {
      console.error('Error selecting file:', error);
      setUploadStatus('Error selecting file: ' + (error.response?.data?.msg || error.message));
    } finally {
      setUploading(false);
      setShowFileSelector(false);
    }
  };

  // Add effect to load previously uploaded files when showing selector
  useEffect(() => {
    if (showFileSelector) {
      fetchPreviousFiles();
    }
  }, [showFileSelector, fetchPreviousFiles]);

  // Add the file selector modal component
  const FileSelector = () => {
    if (!showFileSelector) return null;
    
    return (
      <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
        <div className="bg-white rounded-lg p-4 max-w-xl w-full max-h-[80vh] flex flex-col">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-lg font-semibold">Select Previously Uploaded File</h3>
            <button 
              onClick={() => setShowFileSelector(false)}
              className="text-gray-500 hover:text-gray-700"
            >
              &times;
            </button>
          </div>
          
          <div className="overflow-y-auto flex-grow">
            {loadingPreviousFiles ? (
              <div className="text-center py-4">Loading files...</div>
            ) : previousFiles.length === 0 ? (
              <div className="text-center py-4">No previously uploaded files found</div>
            ) : (
              <ul className="divide-y divide-gray-200">
                {previousFiles.map((file) => (
                  <li key={file.file_id} className="py-3 hover:bg-gray-50">
                    <button
                      onClick={() => selectPreviousFile(file.file_id, file.filename)}
                      className="w-full text-left flex items-center p-2"
                    >
                      <FiFile className="text-blue-500 mr-3" size={18} />
                      <div>
                        <div className="font-medium">{file.filename}</div>
                        <div className="text-xs text-gray-500">
                          Uploaded: {new Date(file.upload_time).toLocaleString()}
                        </div>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
          
          <div className="mt-4 border-t pt-3 flex justify-end">
            <button
              onClick={() => setShowFileSelector(false)}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-100"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className="flex h-screen bg-gray-100">
      {/* Sidebar for conversations list */}
      <Sidebar
        conversations={conversations}
        currentConversationId={conversationId}
        onNewChat={handleNewChat}
        onDeleteConversation={handleDeleteConversation}
        onRenameConversation={handleRenameConversation}
        onLogout={handleLogout}
        isOpen={isSidebarOpen}
        onToggle={() => setIsSidebarOpen(!isSidebarOpen)}
      />

      {/* Main chat area */}
      <div className="flex-1 flex flex-col">
        {/* Chat header */}
        <header className="bg-white shadow z-10">
          <div className="w-full flex flex-row items-center justify-between py-4 px-6">
            <div className="flex items-center w-1/2">
              <button
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                className="mr-4 text-gray-500 lg:hidden"
              >
                ☰
              </button>
              <h1 className="text-xl font-bold text-gray-900 truncate">
                {currentConversation?.title || 'New Conversation'}
              </h1>
            </div>
            <div className="flex items-center w-1/2 justify-end">
              <button
                onClick={handleNewChat}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                New Chat
              </button>
            </div>
          </div>
        </header>

        {/* Chat messages */}
        <div className="flex-1 overflow-auto p-4 bg-white">
          {/* Only show error if it's NOT a rename error (e.g., sending message, loading, etc.) */}
          {error && !error.includes('rename conversation') && (
            <div className="p-4 bg-red-50 text-red-500 rounded-md mb-4">
              {error}
            </div>
          )}

          <div className="space-y-6">
            {messages.map((msg, index) => {
              // Only render user+assistant pairs for version toggling
              if (msg.role === 'user') {
                const assistantMsg = messages[index + 1] && messages[index + 1].role === 'assistant' ? messages[index + 1] : null;
                return (
                  <React.Fragment key={index}>
                    <div
                      ref={el => messageRefs.current[index] = el}
                      className={`group flex flex-col items-end w-full`}
                      id={`msg-${index}`}
                    >
                      {/* Show file info if this message has an attached file */}
                      {msg.hasFile && msg.fileName && (
                        <div className="mb-2 p-2 bg-blue-50 rounded-lg border border-blue-200 self-end mr-2" style={{ maxWidth: '60%' }}>
                          <div className="flex items-center">
                            <FaPaperclip className="text-blue-500 mr-2" />
                            <div className="flex-1">
                              <div className="text-xs text-blue-700">File attached:</div>
                              <div className="text-sm font-medium text-blue-600 truncate" style={{ maxWidth: '250px' }}>
                                {msg.fileName}
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                      
                      {/* Show reply context if this user message is a reply (above the bubble, always persist) */}
                      {msg.replyTo && (
                        <div
                          className="mb-1 px-2 py-1 bg-gray-50 border-l-4 border-primary-400 rounded text-xs text-gray-700 max-w-xs truncate self-end cursor-pointer hover:bg-yellow-100"
                          style={{ maxWidth: '350px', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}
                          onClick={() => {
                            if (msg.replyTo.index !== undefined) {
                              const el = document.getElementById(`msg-${msg.replyTo.index}`);
                              if (el) {
                                el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                                el.classList.add('highlight-reply');
                                setTimeout(() => el.classList.remove('highlight-reply'), 1500);
                              }
                            }
                          }}
                          title="Click to view replied message"
                        >
                          Replying to: {getReplyPreview(msg.replyTo.content)}
                        </div>
                      )}
                      <div className="flex items-center justify-end w-full">
                        {/* Action icons (copy, edit, reply, version toggle) */}
                        <div className="flex gap-2 mr-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                          <button
                            onClick={() => {
                              navigator.clipboard.writeText(getPairDisplayedContent(msg, index));
                            }}
                            title="Copy message"
                            className="p-1 rounded hover:bg-gray-200 focus:outline-none"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
                              <rect x="3" y="3" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
                            </svg>
                          </button>
                          <button
                            onClick={() => {
                              setEditingMsgIdx(index);
                              setEditingMsgValue(getPairDisplayedContent(msg, index));
                            }}
                            title="Edit message"
                            className="p-1 rounded hover:bg-gray-200 focus:outline-none"
                            disabled={editLoading}
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15.232 5.232l3.536 3.536M9 13l6.586-6.586a2 2 0 112.828 2.828L11.828 15.828a2 2 0 01-2.828 0L9 13zm0 0V21h8" />
                            </svg>
                          </button>
                          <button
                            onClick={() => {
                              // Use the currently displayed content (which may be an edited version)
                              const currentDisplayedContent = getPairDisplayedContent(msg, index);
                              // Create a modified message object with the current version for the reply
                              const replyMsg = {
                                ...msg,
                                content: currentDisplayedContent
                              };
                              setReplyTo({ index, msg: replyMsg });
                            }}
                            title="Reply to message"
                            className="p-1 rounded hover:bg-gray-200 focus:outline-none"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="black" viewBox="0 0 24 24">
                              <path d="M21 11H6.41l5.3-5.29a1 1 0 10-1.42-1.42l-7 7a1 1 0 000 1.42l7 7a1 1 0 001.42-1.42L6.41 13H21a1 1 0 100-2z"/>
                            </svg>
                          </button>
                          {/* Version toggle arrows for the pair */}
                          {msg.versions && msg.versions.length > 0 && (
                            <div className="flex items-center gap-1 ml-1">
                              <button
                                onClick={() => handlePairVersionToggle(index, 1)}
                                disabled={(pairVersionIdx[index] || 0) >= msg.versions.length}
                                className="p-1 text-xs rounded hover:bg-gray-200"
                                title="Previous version"
                              >
                                &#8592;
                              </button>
                              <span className="text-xs">{(pairVersionIdx[index] || 0) + 1}/{(msg.versions?.length || 0) + 1}</span>
                              <button
                                onClick={() => handlePairVersionToggle(index, -1)}
                                disabled={(pairVersionIdx[index] || 0) <= 0}
                                className="p-1 text-xs rounded hover:bg-gray-200"
                                title="Next version"
                              >
                                &#8594;
                              </button>
                            </div>
                          )}
                        </div>
                        {/* Message bubble or edit input */}
                        {editingMsgIdx === index ? (
                          <form
                            onSubmit={e => {
                              e.preventDefault();
                              handleEditSubmit(index);
                            }}
                            className="w-full"
                          >
                            <div className="w-full bg-white rounded-lg p-0">
                              <textarea
                                value={editingMsgValue}
                                onChange={e => setEditingMsgValue(e.target.value)}
                                className="w-full min-h-[80px] rounded-lg border-none py-3 px-4 focus:ring-2 focus:ring-primary-500 focus:border-primary-500 resize-vertical"
                                rows={4}
                                autoFocus
                                onKeyDown={e => {
                                  if (e.key === 'Escape') {
                                    setEditingMsgIdx(null);
                                    setEditingMsgValue('');
                                  }
                                }}
                                disabled={editLoading}
                                style={{ fontSize: '1rem', lineHeight: '1.5', background: 'transparent' }}
                              />
                            </div>
                            <div className="flex gap-2 mt-2">
                              <button
                                type="submit"
                                className="px-3 py-1 rounded bg-primary-600 text-white hover:bg-primary-700"
                                title="Save edit"
                                disabled={editLoading}
                              >
                                {editLoading ? 'Saving...' : 'Save'}
                              </button>
                              <button
                                type="button"
                                className="px-3 py-1 rounded bg-gray-300 text-gray-700 hover:bg-gray-400"
                                onClick={() => {
                                  setEditingMsgIdx(null);
                                  setEditingMsgValue('');
                                }}
                                title="Cancel edit"
                                disabled={editLoading}
                              >
                                Cancel
                              </button>
                              {editError && <span className="text-xs text-red-600 ml-2">{editError}</span>}
                            </div>
                          </form>
                        ) : (
                          <div className="max-w-3xl rounded-lg px-4 py-2 bg-primary-600 text-white">
                            <ReactMarkdown components={components}>
                              {getPairDisplayedContent(msg, index)}
                            </ReactMarkdown>
                          </div>
                        )}
                      </div>
                    </div>
                    {/* Assistant response for this user message */}
                    {assistantMsg && (
                      <div
                        ref={el => messageRefs.current[index + 1] = el}
                        className={`group flex flex-col items-start`}
                        id={`msg-${index + 1}`}
                      >
                        <div className="flex items-center justify-start w-full">
                          <div className="max-w-3xl rounded-lg px-4 py-2 bg-gray-100 text-gray-800">
                            <ReactMarkdown components={components}>
                              {getPairDisplayedContent(assistantMsg, index, true)}
                            </ReactMarkdown>
                          </div>
                          {/* Action icons for assistant messages (copy, reply) */}
                          <div className="flex gap-2 ml-2 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(getPairDisplayedContent(assistantMsg, index, true));
                              }}
                              title="Copy message"
                              className="p-1 rounded hover:bg-gray-200 focus:outline-none"
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
                                <rect x="3" y="3" width="13" height="13" rx="2" stroke="currentColor" strokeWidth="2" fill="none"/>
                              </svg>
                            </button>
                            <button
                              onClick={() => {
                                // Use the currently displayed content (which may be an edited version)
                                const currentDisplayedContent = getPairDisplayedContent(assistantMsg, index, true);
                                // Create a modified message object with the current version for the reply
                                const replyMsg = {
                                  ...assistantMsg,
                                  content: currentDisplayedContent
                                };
                                setReplyTo({ index: index + 1, msg: replyMsg });
                              }}
                              title="Reply to message"
                              className="p-1 rounded hover:bg-gray-200 focus:outline-none"
                            >
                              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="black" viewBox="0 0 24 24">
                                <path d="M21 11H6.41l5.3-5.29a1 1 0 10-1.42-1.42l-7 7a1 1 0 000 1.42l7 7a1 1 0 001.42-1.42L6.41 13H21a1 1 0 100-2z"/>
                              </svg>
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                );
              }
              // Don't render assistant messages here (they are rendered with their user pair)
              return null;
            })}
            
            {/* Streaming response */}
            {streamingResponse && (
              <div className="flex justify-start">
                <div className="max-w-3/4 p-3 rounded-lg bg-gray-200 text-gray-800">
                  <ReactMarkdown components={components}>
                    {streamingResponse}
                  </ReactMarkdown>
                </div>
              </div>
            )}
            
            {isLoading && !streamingResponse && (
              <div className="flex justify-start">
                <div className="max-w-3/4 p-3 rounded-lg bg-gray-200 text-gray-800">
                  <div className="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            )}
            <div ref={messageEndRef} />
          </div>
        </div>

        {/* File upload and message input row */}
        <div className="bg-white border-t border-gray-200 p-4">
          {autoSearchActive && (
            <div className="mb-2 text-xs text-blue-600 flex items-center">
              <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-4 h-4 mr-1">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 0 1 7.843 4.582M12 3a8.997 8.997 0 0 0-7.843 4.582m15.686 0A11.953 11.953 0 0 1 12 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0 1 21 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0 1 12 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 0 1 3 12c0-1.605.42-3.113 1.157-4.418" />
              </svg>
              Web search was automatically used to provide the most current information
            </div>
          )}
          {replyTo && (
            <div
              className="mb-2 p-2 bg-gray-100 border-l-4 border-primary-500 rounded relative cursor-pointer hover:bg-yellow-100"
              style={{ maxWidth: '350px', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}
              onClick={() => {
                if (replyTo.index !== undefined) {
                  const el = document.getElementById(`msg-${replyTo.index}`);
                  if (el) {
                    el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    el.classList.add('highlight-reply');
                    setTimeout(() => el.classList.remove('highlight-reply'), 1500);
                  }
                }
              }}
              title="Click to view replied message"
            >
              <span className="text-xs text-gray-600">Replying to:</span>
              <div className="text-sm text-gray-800 truncate">{getReplyPreview(replyTo.msg?.content)}</div>
              <button
                className="absolute top-1 right-2 text-gray-400 hover:text-red-500"
                onClick={e => { e.stopPropagation(); setReplyTo(null); }}
                title="Cancel reply"
              >
                &times;
              </button>
            </div>
          )}
          
          {/* Show file tag above input only if not locked (not yet sent with a message) */}
          {uploadedFileDisplay && !fileLocked && (
            <div className="mb-2 flex items-center">
              <div className="flex items-center bg-blue-100 text-blue-800 rounded-md px-3 py-1 text-sm font-medium mr-2">
                <span className="truncate max-w-[180px]">{uploadedFileDisplay}</span>
                {uploadStatus && (
                  <span className={`ml-3 text-xs ${uploadStatus.includes('success') ? 'text-green-600' : 'text-red-600'}`}>
                    {uploadStatus}
                  </span>
                )}
                <button
                  onClick={clearUploadedFile}
                  className="ml-2 text-blue-400 hover:text-red-500 focus:outline-none"
                  aria-label="Remove file"
                  style={{ fontSize: '1.1em', fontWeight: 'bold', background: 'none', border: 'none', cursor: 'pointer' }}
                >
                  ×
                </button>
              </div>
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="flex items-end gap-2">
            {/* Attachment icons */}
            <div className="flex">
              <button
                type="button"
                className="p-2 rounded-full hover:bg-gray-200 text-gray-500"
                onClick={() => fileInputRef.current && fileInputRef.current.click()}
                tabIndex={0}
                aria-label="Attach file"
              >
                <FaPaperclip size={20} />
              </button>
              <button
                type="button"
                className="p-2 rounded-full hover:bg-gray-200 text-gray-500"
                onClick={() => setShowFileSelector(true)}
                tabIndex={0}
                aria-label="Select previous file"
              >
                <FaHistory size={20} />
              </button>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.json,.pdf,.docx"
              onChange={handleFileUpload}
              style={{ display: 'none' }}
            />
            {/* Web search toggle button - globe */}
            <button
              type="button"
              onClick={() => setWebSearchEnabled(!webSearchEnabled)}
              className={`p-2 rounded-full ml-1 ${webSearchEnabled ? 'bg-blue-100 text-blue-600 hover:bg-blue-200' : 'bg-gray-200 text-gray-500 hover:bg-gray-300'}`}
              title={webSearchEnabled ? "Web search enabled - click send to search" : "Click to enable web search"}
              aria-label={webSearchEnabled ? "Web search enabled" : "Enable web search"}
            >
              <FiGlobe size={20} />
            </button>
            {/* Textarea for message input */}
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyDown={handleInputKeyDown}
              disabled={isLoading}
              placeholder="Ask a cybersecurity question..."
              className="flex-1 rounded-md border border-gray-300 py-2 px-4 focus:ring-2 focus:ring-primary-500 focus:border-primary-500 resize-none min-h-[64px] max-h-40"
              rows={2}
              spellCheck={true}
            />
            {/* Up-arrow send button */}
            <button
              type="submit"
              disabled={isLoading || !message.trim()}
              className={`ml-2 p-0 w-10 h-10 flex items-center justify-center rounded-full ${isLoading || !message.trim() ? 'bg-gray-300 text-gray-500' : 'bg-primary-600 text-white hover:bg-primary-700'}`}
              aria-label="Send message"
            >
              <FiArrowUp size={22} />
            </button>
          </form>
          {uploading && <span className="text-xs text-blue-600 ml-2">Uploading...</span>}
        </div>
      </div>

      {/* Add File Selector Modal */}
      <FileSelector />
    </div>
  );
};

export default Chat; 