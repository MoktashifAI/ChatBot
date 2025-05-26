import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const Sidebar = ({
  conversations,
  currentConversationId,
  onNewChat,
  onDeleteConversation,
  onRenameConversation,
  onLogout,
  isOpen,
  onToggle
}) => {
  const [editingId, setEditingId] = useState(null);
  const [editTitle, setEditTitle] = useState('');
  const [search, setSearch] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [searching, setSearching] = useState(false);
  const [errorModal, setErrorModal] = useState({ open: false, message: '' });

  useEffect(() => {
    if (!search.trim()) {
      setSearchResults([]);
      setSearching(false);
      return;
    }
    setSearching(true);
    const timeout = setTimeout(async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get(`/conversations/search?q=${encodeURIComponent(search)}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setSearchResults(res.data.results || []);
      } catch (err) {
        setSearchResults([]);
      } finally {
        setSearching(false);
      }
    }, 300);
    return () => clearTimeout(timeout);
  }, [search]);

  const handleEdit = (conv) => {
    setEditingId(conv.id);
    setEditTitle(conv.title);
  };

  const handleSave = async (id) => {
    if (editTitle.trim()) {
      const result = await onRenameConversation(id, editTitle.trim());
      if (result && result.error) {
        setErrorModal({ open: true, message: result.error });
      }
    }
    setEditingId(null);
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'Unknown date';
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return 'Unknown date';
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const month = months[date.getMonth()];
    const day = String(date.getDate()).padStart(2, '0');
    const year = date.getFullYear();
    let hour = date.getHours();
    let minute = String(date.getMinutes()).padStart(2, '0');
    const ampm = hour >= 12 ? 'PM' : 'AM';
    hour = hour % 12;
    hour = hour ? hour : 12;
    return `${month} ${day} ${year}, ${hour}:${minute} ${ampm}`;
  };

  // Utility to highlight search terms in text
  function highlightText(text, keyword) {
    if (!keyword) return text;
    const regex = new RegExp(`(${keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    return text.split(regex).map((part, i) =>
      regex.test(part) ? <mark key={i} className="bg-yellow-200 text-gray-900 px-0.5 rounded">{part}</mark> : part
    );
  }

  const ErrorModal = ({ open, message, onClose }) => {
    if (!open) return null;
    return (
      <div className="fixed inset-0 flex items-center justify-center z-50">
        <div className="bg-black bg-opacity-50 absolute inset-0"></div>
        <div className="relative bg-white rounded shadow-lg p-6 w-80 max-w-full text-gray-900 animate-fade-in">
          <div className="flex justify-between items-center mb-2">
            <span className="font-semibold text-red-600">Error</span>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-700 text-lg font-bold"
              aria-label="Close error modal"
            >
              ×
            </button>
          </div>
          <div className="text-sm">{message}</div>
        </div>
      </div>
    );
  };

  return (
    <>
      <ErrorModal open={errorModal.open} message={errorModal.message} onClose={() => setErrorModal({ open: false, message: '' })} />
      <div
        className={`${isOpen ? 'translate-x-0' : '-translate-x-full'} transform transition-transform duration-300 ease-in-out fixed inset-y-0 left-0 z-30 w-64 bg-gray-800 text-white lg:relative lg:translate-x-0`}
      >
        <div className="h-full flex flex-col">
          {/* Header, search, and new chat button */}
          <div className="p-4 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <h2 className="text-xl font-semibold text-left flex-1">Moktashif</h2>
              <button
                onClick={onNewChat}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
              >
                New Chat
              </button>
              <button
                onClick={onToggle}
                className="lg:hidden text-gray-300 hover:text-white"
              >
                ×
              </button>
            </div>
            {/* Search bar with icon */}
            <div className="relative mt-4">
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search conversations..."
                className="w-full pl-9 pr-8 py-1 rounded bg-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
              <span className="absolute left-2 top-1.5 text-gray-400">
                {/* SVG search icon */}
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </span>
              {search && (
                <button
                  className="absolute right-2 top-1.5 text-gray-400 hover:text-white"
                  onClick={() => setSearch('')}
                  aria-label="Clear search"
                  tabIndex={0}
                >
                  ×
                </button>
              )}
            </div>
          </div>

          {/* Conversations list or search results */}
          <div className="flex-1 overflow-y-auto p-2 custom-scrollbar">
            <div className="space-y-1">
              {search.trim() ? (
                searching ? (
                  <div className="text-center text-gray-400 py-4 animate-pulse">Searching...</div>
                ) : searchResults.length > 0 ? (
                  searchResults.map((conv) => (
                    <div key={conv.id} className="mb-2">
                      <Link
                        to={
                          conv.match_type === 'message' && conv.matches && conv.matches.length > 0
                            ? `/chat/${conv.id}#msg-${conv.matchIndexes && conv.matchIndexes[0] !== undefined ? conv.matchIndexes[0] : 0}`
                            : `/chat/${conv.id}`
                        }
                        className={`block p-2 text-sm rounded-md text-left ${conv.id === currentConversationId ? 'bg-gray-700' : 'hover:bg-gray-700'}`}
                        style={{ paddingLeft: 0 }}
                      >
                        <div className="flex flex-col">
                          <span className="truncate font-medium" style={{ textAlign: 'left' }}>
                            {conv.match_type === 'title' ? (
                              highlightText(conv.title, search)
                            ) : (
                              conv.title
                            )}
                          </span>
                          {conv.match_type === 'message' && conv.snippet && (
                            <span className="text-xs text-primary-300 mt-1">
                              ...{highlightText(conv.snippet, search)}...
                            </span>
                          )}
                        </div>
                        <div className="text-xs text-gray-400 mt-1">
                          {formatDate(conv.created_at || conv.updated_at)}
                        </div>
                      </Link>
                      {/* Show all matches per conversation if available */}
                      {conv.matches && conv.matches.length > 1 && conv.matchIndexes && (
                        <div className="ml-2 mt-1 space-y-1">
                          {conv.matches.slice(1, 4).map((m, idx) => (
                            <Link
                              key={idx}
                              to={`/chat/${conv.id}#msg-${conv.matchIndexes[idx + 1]}`}
                              className="block text-xs text-primary-300 hover:underline"
                              style={{ textAlign: 'left', paddingLeft: 0 }}
                            >
                              ...{highlightText(m, search)}...
                            </Link>
                          ))}
                          {conv.matches.length > 4 && (
                            <div className="text-xs text-gray-400">+{conv.matches.length - 4} more matches</div>
                          )}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="text-center text-gray-400 py-4">No results found</div>
                )
              ) : conversations.length > 0 ? (
                conversations.map((conv) => (
                  <div
                    key={conv.id}
                    className={`rounded-md ${conv.id === currentConversationId ? 'bg-gray-700' : 'hover:bg-gray-700'}`}
                  >
                    {editingId === conv.id ? (
                      <div className="p-2">
                        <input
                          type="text"
                          value={editTitle}
                          onChange={(e) => setEditTitle(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') handleSave(conv.id);
                            if (e.key === 'Escape') setEditingId(null);
                          }}
                          autoFocus
                          className="w-full bg-gray-600 text-white px-2 py-1 rounded outline-none"
                        />
                        <div className="flex mt-1 space-x-2">
                          <button
                            onClick={() => handleSave(conv.id)}
                            className="text-xs text-gray-300 hover:text-white"
                          >
                            Save
                          </button>
                          <button
                            onClick={() => setEditingId(null)}
                            className="text-xs text-gray-300 hover:text-white"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <Link
                        to={`/chat/${conv.id}`}
                        className="block p-2 text-sm"
                        style={{ paddingLeft: 0 }}
                      >
                        <div className="flex justify-between items-start">
                          <div className="truncate font-medium" style={{ textAlign: 'left' }}>{conv.title}</div>
                          <div className="flex space-x-1 ml-1">
                            <button
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                handleEdit(conv);
                              }}
                              className="text-gray-400 hover:text-white"
                            >
                              ✎
                            </button>
                            <button
                              onClick={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                if (window.confirm('Delete this conversation?')) {
                                  onDeleteConversation(conv.id);
                                }
                              }}
                              className="text-gray-400 hover:text-white"
                            >
                              🗑️
                            </button>
                          </div>
                        </div>
                        <div className="text-xs text-gray-400 mt-1">
                          {formatDate(conv.created_at || conv.updated_at)}
                        </div>
                      </Link>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-4 text-gray-400">
                  No conversations yet
                </div>
              )}
            </div>
          </div>

          {/* Logout */}
          <div className="p-4 border-t border-gray-700">
            <button
              onClick={onLogout}
              className="w-full text-left px-3 py-2 rounded-md text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
            >
              Log out
            </button>
          </div>
        </div>
      </div>
      {/* Custom scrollbar styles */}
      <style>{`
        .custom-scrollbar::-webkit-scrollbar {
          width: 8px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
          background: #1f2937;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
          background: #374151;
          border-radius: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
          background: #4b5563;
        }
        .custom-scrollbar {
          scrollbar-width: thin;
          scrollbar-color: #374151 #1f2937;
        }
      `}</style>
    </>
  );
};

export default Sidebar;