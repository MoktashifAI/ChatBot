# CyberSecGPT Frontend Preview

## UI Preview

### Login Screen
```
+----------------------------------------------------------+
|                                                          |
|                      CyberSecGPT                         |
|                Your Cybersecurity Assistant             |
|                                                          |
|  +----------------------------------------------------+  |
|  |                    Username                        |  |
|  +----------------------------------------------------+  |
|                                                          |
|  +----------------------------------------------------+  |
|  |                    Password                        |  |
|  +----------------------------------------------------+  |
|                                                          |
|  +----------------------------------------------------+  |
|  |                     Sign in                        |  |
|  +----------------------------------------------------+  |
|                                                          |
|  Don't have an account? Sign up                          |
|                                                          |
+----------------------------------------------------------+
```

### Chat Interface with Sidebar
```
+----------------------------------------------------------+
| CyberSecGPT  | Chat Title                   | New Chat   |
|--------------|------------------------------|------------|
| New Chat     |                                          |
|              |                                          |
| SQL Injection|                                          |
| Apr 17, 12:30|                                          |
|              |   User message bubble aligned to right   |
| XSS Defense  |                                          |
| Apr 16, 3:45 |                                          |
|              |                                          |
| Secure API   |   Bot message bubble aligned to left     |
| Apr 15, 10:15|   with syntax highlighting for code:     |
|              |   ```python                              |
| CSRF Tutorial|   def secure_function():                 |
| Apr 14, 2:20 |       print("secure code here")          |
|              |   ```                                     |
|              |                                          |
|              |                                          |
|              |                                          |
|              |                                          |
|              +------------------------------------------+
|              | Ask a cybersecurity question...  | Send  |
+--------------+------------------------------------------+
```

## How to Integrate with Your Backend

To integrate this frontend with your cybersecurity chat backend:

1. **Run Your Flask Backend**: 
   ```bash
   cd app/tools
   python chat.py
   ```
   This will start your Flask server on port 5000.

2. **Start the React Frontend**: 
   ```bash
   cd app/frontend
   npm install  # First time only
   npm start
   ```
   This will start your React application on port 3000.

3. **Flow of Data**:
   - Frontend makes API calls to endpoints like `/login`, `/signup`, `/conversations/new`, etc.
   - Backend processes these requests and interacts with the database
   - The LLM-powered responses are returned to the frontend
   - Frontend displays messages with formatting and syntax highlighting

4. **Authentication Flow**:
   - User registers or logs in through the frontend
   - Backend generates and returns a JWT token
   - Frontend stores this token in localStorage
   - Subsequent requests include this token in the Authorization header
   - Authenticated routes in the backend verify this token

5. **New Chat Functionality**:
   - User clicks "New Chat" button
   - Frontend sends a request to create a new conversation
   - Backend creates a new conversation in the database with a unique ID
   - Frontend redirects to the new conversation URL
   - User can type and send messages in this new conversation 