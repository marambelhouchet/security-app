import hashlib
import json
from collections import OrderedDict
import re
from threading import Lock
import logging

import requests

class ResponseCache:
    """LRU Cache with SHA-256 key generation."""
    def __init__(self, max_size=500):
        """
        Initialize the cache with a maximum size.
        Uses an OrderedDict to maintain the order of cache entries.
        """
        self.max_size = max_size
        self.cache = OrderedDict()
        self.lock = Lock()

    def generate_key(self, content: str, alert_type: str, gravity: str, model: str, language: str) -> str:
        """
        Generate a unique cache key based on input parameters.
        Combines normalized JSON content, alert type, gravity, model, and language.
        """
        try:
            # Normalize JSON content
            data = json.loads(content)
            normalized = json.dumps(data, sort_keys=True)
        except json.JSONDecodeError:
            normalized = content  # Use raw content if JSON decoding fails

        key_str = f"{normalized}_{alert_type}_{gravity}_{model}_{language}"
        return hashlib.sha256(key_str.encode()).hexdigest()

    def get(self, key: str) -> str | None:
        """
        Retrieve a value from the cache in a thread-safe manner.
        Marks the entry as recently used if it exists.
        """
        with self.lock:
            if key in self.cache:
                self.cache.move_to_end(key)  # Mark as recently used
                return self.cache[key]
            return None

    def set(self, key: str, value: str) -> None:
        """
        Add a value to the cache and evict the oldest entry if the cache is full.
        """
        with self.lock:
            self.cache[key] = value
            self.cache.move_to_end(key)
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)  # Remove the least recently used item

def generate_response(model: str, prompt: str, file_content: str, alert_type: str, gravity: str, mongo_collection) -> str:
    """
    Generate a response using the LLM and cache recommendations.

    Parameters:
        model (str): The name of the LLM model to use.
        prompt (str): The base prompt to send to the LLM.
        file_content (str): The content of the uploaded file.
        alert_type (str): The type of alert.
        gravity (str): The severity level of the alert.
        mongo_collection: The MongoDB collection used to retrieve recommendations.

    Returns:
        str: The generated response text.
    """
    try:
        AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]

        if model not in AVAILABLE_MODELS:
            raise ValueError(f"Model '{model}' not available")

        # Retrieve context with recommendations
        from rag import retrieve_context  # Import RAG function
        rag_context = retrieve_context(file_content, alert_type, gravity, mongo_collection)

        # Check if recommendations exist in the context
        if "No relevant recommendations found." not in rag_context:
            # Extract immediate actions and recommended actions from the context
            immediate_actions_start = rag_context.find("Immediate Actions:")
            recommended_actions_start = rag_context.find("Recommended Actions if the Issue Persists:")

            immediate_actions = rag_context[immediate_actions_start:recommended_actions_start].strip()
            recommended_actions = rag_context[recommended_actions_start:].strip()

            # Build the prompt with recommendations directly from MongoDB
            full_prompt = f"""[{gravity} Alert] {prompt}

{rag_context}

Input Data:
{file_content}

Note: The following recommendations are retrieved from the database:
{immediate_actions}

{recommended_actions}
"""
        else:
            # If no recommendations are found, use the default prompt
            full_prompt = f"""[{gravity} Alert] {prompt}

{rag_context}

Input Data:
{file_content}"""

        # Send the request to the LLM API
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {"temperature": 0.7, "max_tokens": 500}
            }
        )
        response.raise_for_status()

        # Remove <think> tags for DeepSeek models
        response_text = response.json().get("response", "").strip()
        if "deepseek" in model.lower():
            response_text = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL).strip()

        return response_text
    except requests.exceptions.RequestException as e:
        logging.error(f"LLM connection error: {str(e)}")
        raise
    except Exception as e:
        logging.error(f"Generation error: {str(e)}")
        raise