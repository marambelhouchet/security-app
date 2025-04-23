# ---------------------------
# Import Required Libraries
# ---------------------------
import logging
import os
import re
from dotenv import load_dotenv
from chromadb import PersistentClient
from pymongo import MongoClient
from sentence_transformers import SentenceTransformer
from chromadb.utils import embedding_functions
import requests
from typing import List, Dict

# ---------------------------
# Load Environment Variables
# ---------------------------
load_dotenv()

# ---------------------------
# Configuration Constants
# ---------------------------
# Database Config
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
MONGO_DB_NAME = 'alertsEngDB'
MONGO_COLLECTION_NAME = 'alerts'
CHROMA_COLLECTION_NAME = "alerts_vectors"
CHROMA_PERSIST_DIR = "./chromadb"

# Model Config
AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", 
                   "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]
EMBEDDING_MODEL_NAME = 'all-MiniLM-L6-v2'

# ---------------------------
# Initialize Components
# ---------------------------
# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MongoDB
try:
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client[MONGO_DB_NAME]
    mongo_collection = mongo_db[MONGO_COLLECTION_NAME]
    logger.info("Connected to MongoDB successfully")
except Exception as e:
    logger.error(f"MongoDB connection failed: {str(e)}")
    raise

# Initialize ChromaDB
try:
    chroma_client = PersistentClient(path=CHROMA_PERSIST_DIR)
    embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL_NAME
    )
    chroma_collection = chroma_client.get_or_create_collection(
        name=CHROMA_COLLECTION_NAME,
        embedding_function=embedding_function
    )
    logger.info("ChromaDB collection initialized successfully")
except Exception as e:
    logger.error(f"ChromaDB initialization failed: {str(e)}")
    raise

# Initialize Embedding Model
embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)

# ---------------------------
# Core Functions
# ---------------------------
def sync_mongodb_to_chromadb(batch_size: int = 100) -> None:
    """
    Synchronize data from MongoDB to ChromaDB with batching and error handling.
    Normalizes field names and text content.
    """
    try:
        total_docs = mongo_collection.count_documents({})
        if total_docs == 0:
            logger.warning("No documents found in MongoDB collection")
            return

        logger.info(f"Starting sync of {total_docs} documents from MongoDB to ChromaDB")

        for batch_num in range(0, total_docs, batch_size):
            alerts = list(mongo_collection.find({}).skip(batch_num).limit(batch_size))
            if not alerts:
                break

            documents, metadatas, ids = [], [], []

            for alert in alerts:
                try:
                    # Required fields check, making `immediate_actions` optional
                    if not all(k in alert for k in ['problem', 'gravity']):
                        logger.warning(f"Skipping document {alert.get('_id')} - missing fields")
                        continue

                    # Get immediate actions with a default if missing
                    immediate = alert.get('immediate_actions', 'N/A')

                    # Normalize recommended actions
                    recommended = alert.get('recommended_next_steps') or alert.get('recommended_actions') or ""

                    # Construct a single text field
                    text = f"Problem: {alert['problem']}\nImmediate Actions: {immediate}\nRecommended Actions: {recommended}"

                    documents.append(text)
                    metadatas.append({
                        'gravity': alert['gravity'],
                        'language': alert.get('language', 'en'),
                        'source': 'mongodb'
                    })
                    ids.append(str(alert['_id']))
                except Exception as doc_error:
                    logger.error(f"Error processing document {alert.get('_id')}: {str(doc_error)}")
                    continue

            if documents:
                chroma_collection.upsert(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                logger.info(f"Processed batch {batch_num//batch_size + 1} ({len(documents)} docs)")

        logger.info("MongoDB to ChromaDB sync completed")

    except Exception as e:
        logger.error(f"Sync failed: {str(e)}")
        raise

def retrieve_context(alert_type: str, gravity: str, language: str = "en") -> str:

    """Retrieve context from ChromaDB using gravity and language filtering"""
    try:
        alert_embedding = embedding_model.encode(alert_type).tolist()

        results = chroma_collection.query(
            query_embeddings=[alert_embedding],
            n_results=5,
            where={
                "$and": [
                    {"gravity": {"$eq": gravity}},
                    {"language": {"$eq": language}}
                ]
            }
        )

        if not results.get("documents"):
            logger.warning(f"No results for {gravity}/{language}")
            return "No recommendations available."

        recommendations = []
        for doc, metadata, distance in zip(results["documents"][0], 
                                           results["metadatas"][0], 
                                           results["distances"][0]):
            confidence = 1 - distance
            if confidence >= 0.7:
                rec_text = (
                    f"Recommendation (Confidence: {confidence:.2f}):\n{doc}\n"
                    f"Source: {metadata.get('source', 'unknown')}\n"
                )
                recommendations.append(rec_text)

        return "\n\n".join(recommendations) if recommendations else "No high-confidence recommendations."

    except Exception as e:
        logger.error(f"Context retrieval error: {str(e)}")
        return "Error retrieving recommendations."


# ---------------------------
# Initialization
# ---------------------------
if __name__ == "__main__":
    try:
        sync_mongodb_to_chromadb()
        logger.info("Application startup completed")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise
