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
    Synchronize data from MongoDB to ChromaDB with support for different recommendation fields.
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
                    # Check for required field 'problem'
                    if 'problem' not in alert:
                        logger.warning(f"Skipping document {alert.get('_id')} - missing problem field")
                        continue

                    # Collect all types of actions/recommendations
                    immediate_actions = alert.get('immediate_actions', [])
                    if isinstance(immediate_actions, list):
                        immediate_actions = "\n".join(f"- {action}" for action in immediate_actions)
                    
                    recommended_actions = alert.get('recommended_actions', [])
                    if isinstance(recommended_actions, list):
                        recommended_actions = "\n".join(f"- {action}" for action in recommended_actions)
                    
                    recommended_next_steps = alert.get('recommended_next_steps', [])
                    if isinstance(recommended_next_steps, list):
                        recommended_next_steps = "\n".join(f"- {step}" for step in recommended_next_steps)

                    # Construct comprehensive text field
                    text_parts = [f"Problem: {alert['problem']}"]
                    
                    if immediate_actions:
                        text_parts.append(f"Immediate Actions:\n{immediate_actions}")
                    
                    if recommended_actions:
                        text_parts.append(f"Recommended Actions:\n{recommended_actions}")
                    
                    if recommended_next_steps:
                        text_parts.append(f"Recommended Next Steps:\n{recommended_next_steps}")

                    text = "\n\n".join(text_parts)

                    documents.append(text)
                    metadatas.append({
                        'gravity': alert.get('gravity', 'Moderate'),
                        'language': alert.get('language', 'en'),
                        'source': 'mongodb',
                        'has_immediate': bool(immediate_actions),
                        'has_recommended': bool(recommended_actions),
                        'has_next_steps': bool(recommended_next_steps)
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
    """Retrieve context from ChromaDB with strict matching of type, gravity, and language"""
    try:
        logger.info(f"Retrieving context for: type={alert_type}, gravity={gravity}, lang={language}")
        alert_embedding = embedding_model.encode(alert_type).tolist()
        
        # Query ChromaDB with proper operator syntax
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

        if not results["documents"]:
            logger.warning(f"No results found for {alert_type}/{gravity}/{language}")
            return "No recommendations available."

        # Use sets to deduplicate recommendations
        immediate_actions = set()
        recommended_actions = set()
        next_steps = set()

        # Process each document
        found_match = False
        for doc in results["documents"][0]:
            logger.debug(f"Processing document: {doc[:100]}...")
            
            sections = doc.split('\n\n')
            current_doc_match = False
            
            # First check if this document matches our alert type
            for section in sections:
                if section.startswith('Problem:'):
                    problem_text = section.replace('Problem:', '').strip().lower()
                    alert_type_lower = alert_type.lower()
                    
                    # Handle French translations
                    if language == 'fr':
                        if alert_type_lower == 'subscribedpower' and 'puissance souscrite' in problem_text:
                            current_doc_match = True
                        # Add other French mappings as needed
                    else:
                        if alert_type_lower in problem_text:
                            current_doc_match = True
                    
                    if current_doc_match:
                        found_match = True
                        logger.info(f"Found matching problem: {problem_text}")
                    break

            if not current_doc_match:
                continue

            # If we found a match, process the recommendations
            for section in sections:
                section = section.strip()
                if section.startswith('Immediate Actions:') or section.startswith('Actions Immédiates:'):
                    actions = [a.strip('- ').strip() for a in section.split('\n')[1:]]
                    for action in actions:
                        if action:
                            immediate_actions.add(action)
                            logger.debug(f"Added immediate action: {action}")
                    
                elif section.startswith('Recommended Actions:') or section.startswith('Actions Recommandées:'):
                    actions = [a.strip('- ').strip() for a in section.split('\n')[1:]]
                    for action in actions:
                        if action:
                            recommended_actions.add(action)
                            logger.debug(f"Added recommended action: {action}")
                
                elif section.startswith('Recommended Next Steps:') or section.startswith('Prochaines Étapes:'):
                    steps = [s.strip('- ').strip() for s in section.split('\n')[1:]]
                    for step in steps:
                        if step:
                            next_steps.add(step)
                            logger.debug(f"Added next step: {step}")

        # Build final recommendations with language-specific headers
        recommendations = []
        headers = {
            'en': {
                'immediate': 'Immediate Actions:',
                'recommended': 'Recommended Actions:',
                'next_steps': 'Recommended Next Steps:'
            },
            'fr': {
                'immediate': 'Actions Immédiates:',
                'recommended': 'Actions Recommandées:',
                'next_steps': 'Prochaines Étapes:'
            }
        }
        
        current_headers = headers.get(language, headers['en'])
        
        if immediate_actions:
            recommendations.append(current_headers['immediate'])
            for action in sorted(immediate_actions):
                recommendations.append(f"• {action}")
            recommendations.append("")
            
        if recommended_actions:
            recommendations.append(current_headers['recommended'])
            for action in sorted(recommended_actions):
                recommendations.append(f"• {action}")
            recommendations.append("")
            
        if next_steps:
            recommendations.append(current_headers['next_steps'])
            for step in sorted(next_steps):
                recommendations.append(f"• {step}")

        if recommendations:
            final_recommendations = "\n".join(recommendations)
            logger.info(f"Found {len(immediate_actions)} immediate, {len(recommended_actions)} recommended actions, and {len(next_steps)} next steps")
            return final_recommendations
        
        logger.warning("No structured recommendations found")
        return "No specific recommendations available for this situation."

    except Exception as e:
        logger.error(f"Context retrieval error: {str(e)}", exc_info=True)
        return f"Error retrieving recommendations: {str(e)}"


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
