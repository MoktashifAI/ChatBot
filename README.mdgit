🚀 Moktashif: Cybersecurity Chat Application


Moktashif is a full-stack cybersecurity chat platform powered by Large Language Models (LLMs). It enables secure document analysis, real-time chat, and persistent semantic memory for enhanced cybersecurity insights.
✨ Features

    🔐 User Authentication (JWT-based)

    💬 Multiple Chat Conversations (create, rename, delete)

    📁 File Upload & Document Analysis

    🧠 LLM-Driven Real-Time Chat (Markdown + Code Highlighting)

    🗃 Persistent Memory & Semantic Search (Pinecone + MongoDB)

    🎨 Responsive UI (React + Tailwind CSS)

⚙️ Prerequisites

    Docker

    Docker Compose

    (Optional for Dev): Node.js v14+, Python 3.10+

📦 Environment Variables

Create a .env file in the root directory with the following values:

# MongoDB
MONGO_URI=mongodb://mongo:27017/vuln_analyzer
JWT_SECRET=your_jwt_secret

# Pinecone (for semantic memory)
PINECONE_API_KEY=your_pinecone_api_key

# LLM API (Groq/OpenAI)
API_KEY=your_llm_api_key
MODEL=your_model_name
BASE_URL=https://api.llm-provider.com
TEMPERATURE=0.6

🚀 Quick Start (Docker Compose)

    Clone the repository:

git clone https://github.com/MoktashifAI/ChatBot.git
cd grad

Add your .env file to the project root.

Build & launch the services:

    docker-compose up --build

    Access the application:

        🌐 Frontend: http://localhost:3000

        🔙 Backend API: http://localhost:5000

        🧩 MongoDB: mongodb://localhost:27017

🧪 Manual Development Setup
📡 Backend (Flask)

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python chat.py

🌐 Frontend (React)

cd frontend
npm install
npm start

🧭 Project Structure

├── chat.py                # Flask backend (entry point)
├── requirements.txt       # Python dependencies
├── frontend/              # React frontend
│   ├── Dockerfile
│   └── ...
├── uploads/               # Uploaded file storage
├── docker-compose.yml     # Service orchestration
├── Dockerfile             # Backend Dockerfile
└── ...

🗒 Notes

    Uploaded files are stored persistently in the uploads/ directory (Docker volume).

    MongoDB data is stored in the mongo-data volume.

    Use strong secrets in .env for production environments.

    Frontend proxies API calls to the backend running on port 5000.
