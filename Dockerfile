# Backend Dockerfile for Flask app
FROM python:3.10-slim

# Set work directory
WORKDIR /app

# Install system dependencies (if needed)
RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create uploads directory
RUN mkdir -p uploads

# Expose Flask port
EXPOSE 5000

# Set environment variables (use .env in compose or bind mount)
ENV FLASK_APP=chat.py

# Run the Flask app
CMD ["python", "chat.py"] 
