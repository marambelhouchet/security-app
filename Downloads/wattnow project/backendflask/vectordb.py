# ---------------------------
# Import Required Libraries
# ---------------------------
import logging  # For logging errors, warnings, and information
import os  # For accessing environment variables
from chromadb import PersistentClient  # For managing ChromaDB collections
from dotenv import load_dotenv  # For loading environment variables from a .env file
from pymongo import MongoClient  # For interacting with MongoDB
from sentence_transformers import SentenceTransformer  # For generating embeddings
from chromadb.utils import embedding_functions  # For embedding function utilities

# ---------------------------
# Load Environment Variables
# ---------------------------
load_dotenv()  # Load variables from a .env file into the environment

# ---------------------------
# Initialize Logging
# ---------------------------
logging.basicConfig(level=logging.INFO)  # Set logging level to INFO

# ---------------------------
# Email Configuration
# ---------------------------
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')  # SMTP server address (default: Gmail)
SMTP_PORT = int(os.getenv('SMTP_PORT', 465))  # SMTP server port (default: 465 for SSL)
SMTP_EMAIL = os.getenv('SMTP_EMAIL')  # Sender email address (retrieved from environment variables)
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')  # Sender email password (retrieved from environment variables)
ALERT_RECIPIENTS = os.getenv('ALERT_RECIPIENTS', '').split(',')  # Default recipients (retrieved from environment variables)

# ---------------------------
# ChromaDB Configuration
# ---------------------------
# Initialize ChromaDB client with a persistent storage path
chroma_client = PersistentClient(path="./chromadb")

# Initialize the embedding model
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')  # Pre-trained model for generating embeddings
embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")  # Embedding function

# Define the ChromaDB collection name
CHROMA_COLLECTION = "alerts_vectors"

# Create or load the ChromaDB collection
try:
    chroma_collection = chroma_client.get_or_create_collection(
        name=CHROMA_COLLECTION,  # Name of the collection
        embedding_function=embedding_function  # Embedding function to use
    )
    logging.info(f"Collection '{CHROMA_COLLECTION}' is ready.")  # Log success message
except Exception as e:
    logging.error(f"Failed to initialize ChromaDB collection: {str(e)}")  # Log error message
    raise  # Raise the exception to stop execution if the collection cannot be initialized

# ---------------------------
# MongoDB Configuration
# ---------------------------
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')  # MongoDB connection URI (default: localhost)
MONGO_DB_NAME = 'alertsEngDB'  # Name of the MongoDB database
MONGO_COLLECTION_NAME = 'alerts'  # Name of the MongoDB collection

# Initialize MongoDB client
mongo_client = MongoClient(MONGO_URI)  # Connect to MongoDB using the URI
mongo_db = mongo_client[MONGO_DB_NAME]  # Access the specified database
mongo_collection = mongo_db[MONGO_COLLECTION_NAME]  # Access the specified collection