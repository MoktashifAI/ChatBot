# Pinecone Memory Store Integration

This document explains how to use the Pinecone vector database for semantic memory in the cybersecurity chat application.

## Overview

The application now supports two memory store implementations:
- MongoDB (original implementation)
- Pinecone (new vector database implementation)

## Configuration

To switch between memory stores, set the `USE_PINECONE` environment variable:

```
# In your .env file
USE_PINECONE=true  # To use Pinecone
USE_PINECONE=false  # To use MongoDB (default)
```

## Migration

To migrate your existing memories from MongoDB to Pinecone:

1. Ensure both MongoDB and Pinecone are properly configured in your `.env` file
2. Run the migration script:
   ```
   python migrate_to_pinecone.py
   ```
3. Once migration is complete, you can switch to using Pinecone by setting `USE_PINECONE=true`

## Implementation Details

- `pinecone_memory_store.py`: Implements the PineconeMemoryStore class
- Uses the same all-MiniLM-L6-v2 embedding model as the MongoDB implementation
- Maintains the same interface as MongoMemoryStore for seamless integration
- Configured to use the "trial" Pinecone index with 384 dimensions

## Benefits of Pinecone

- Specialized vector database optimized for similarity search
- Better performance for semantic retrieval at scale
- Serverless architecture that scales automatically
- Advanced filtering capabilities for complex queries

## Troubleshooting

If you encounter issues:
1. Check that your Pinecone API key is correctly set in `.env`
2. Verify that the "trial" index exists in your Pinecone account
3. Ensure the index is configured for 384 dimensions (matching all-MiniLM-L6-v2)
