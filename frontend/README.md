# CyberSecGPT Frontend

This is the frontend for the CyberSecGPT cybersecurity chat application. It provides a user interface for interacting with the cybersecurity chatbot.

## Features

- User authentication (signup/login)
- Multiple chat conversations (similar to ChatGPT)
- Create, rename and delete conversations
- Responsive design that works on mobile and desktop
- Markdown support for code syntax highlighting
- Real-time message updates

## Prerequisites

- Node.js (version 14 or higher)
- npm or yarn
- Backend server running on port 5000

## Installation

1. Install dependencies:
   ```bash
   cd app/frontend
   npm install
   ```

2. Start the development server:
   ```bash
   npm start
   ```

The application will be available at http://localhost:3000 and will proxy API requests to the Flask backend running on port 5000.

## Building for Production

To create an optimized production build:

```bash
npm run build
```

This will create a `build` directory with optimized files ready for deployment.

## Integration with Backend

This frontend is designed to work with the Flask backend API in `app/tools/chat.py`. The API proxy is configured in `package.json` to forward requests to http://localhost:5000.

## Key Components

- **Authentication**: Sign up and login forms with JWT authentication
- **Chat Interface**: Real-time chat with markdown support
- **Conversation Management**: Create, rename, delete, and switch between multiple conversations
- **Responsive Design**: Works on mobile and desktop with a collapsible sidebar

## Technologies Used

- React
- React Router
- Axios for API requests
- Tailwind CSS for styling
- React Markdown for rendering markdown in messages
- Syntax highlighting for code blocks 