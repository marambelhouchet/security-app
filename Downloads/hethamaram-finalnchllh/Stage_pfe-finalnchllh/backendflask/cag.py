import hashlib
import json
from collections import OrderedDict
import re
from threading import Lock
import logging
from chromadb import logger
import requests
from promptengeneering import get_alert_prompt
from rag import retrieve_context
AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]

class ResponseCache:
    """LRU Cache with processed data comparison."""
    def __init__(self, max_size=500):
        self.max_size = max_size
        self.cache = OrderedDict()  # {hash: (processed_data, response)}
        self.lock = Lock()

    def generate_key(self, processed_content: dict) -> str:
        """Generate hash key from processed content only."""
        try:
            # Sort keys to ensure consistent ordering
            normalized = json.dumps(processed_content, sort_keys=True)
            return hashlib.sha256(normalized.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Key generation error: {str(e)}")
            return None

    def get(self, processed_content: dict) -> str | None:
        """Check if identical processed data exists in cache."""
        key = self.generate_key(processed_content)
        if not key:
            return None

        with self.lock:
            if key in self.cache:
                stored_data, response = self.cache[key]
                # Compare actual data, not just keys
                if json.dumps(stored_data, sort_keys=True) == json.dumps(processed_content, sort_keys=True):
                    self.cache.move_to_end(key)
                    logger.info("Cache hit: Found identical processed data")
                    return response
            return None

    def set(self, processed_content: dict, response: str) -> None:
        """Store both processed data and response."""
        key = self.generate_key(processed_content)
        if not key:
            return

        with self.lock:
            self.cache[key] = (processed_content, response)
            self.cache.move_to_end(key)
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

# Initialize cache at module level
response_cache = ResponseCache(max_size=500)

def generate_llm_response(model: str, full_prompt: str) -> str:
    """
    Send request to LLM API and return the response.
    """
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": full_prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "max_tokens": 500,
                    "top_p": 0.9
                }
            }
        )
        response.raise_for_status()
        
        response_text = response.json().get("response", "").strip()
        if "deepseek" in model.lower():
            response_text = re.sub(r'<think>.*?</think>', '', response_text, flags=re.DOTALL).strip()
        
        return response_text

    except requests.exceptions.RequestException as e:
        logger.error(f"LLM connection error: {str(e)}")
        return f"Error connecting to AI service: {str(e)}"
    except Exception as e:
        logger.error(f"LLM response generation error: {str(e)}")
        return f"Error generating response: {str(e)}"

def generate_response(model: str, processed_content: dict, alert_type: str, gravity: str, language: str = "en") -> str:    
    try:
        if model not in AVAILABLE_MODELS:
            raise ValueError(f"Model '{model}' not available")

        # Get prompt template
        prompt_config = get_alert_prompt(alert_type, model)
        if not prompt_config:
            raise ValueError(f"No prompt template found for alert_type: {alert_type}")

        prompt_template = prompt_config.get(language, prompt_config.get('en'))
        if not prompt_template:
            raise ValueError(f"No template found for language: {language}")

        # Check CAG cache first for identical processed data
        cached_response = response_cache.get(processed_content)
        if cached_response:
            logger.info(f"Using cached response for alert_type={alert_type}")
            return cached_response

        try:
            # Try RAG first
            rag_context = retrieve_context(alert_type, gravity, language)
            if rag_context and "No recommendations available." not in rag_context:
                logger.info(f"RAG successful for alert_type={alert_type}")
                # Format prompt with RAG context
                formatted_prompt = prompt_template.format(**processed_content)
                full_prompt = f"{formatted_prompt}{rag_context}"
            else:
                # Use template without RAG
                full_prompt = prompt_template.format(**processed_content)

            # Generate response
            response = generate_llm_response(model, full_prompt)
            
            # Cache the new response with the processed data
            response_cache.set(processed_content, response)
            logger.info(f"Cached new response for alert_type={alert_type}")
            
            return response

        except Exception as e:
            logger.error(f"RAG retrieval error: {str(e)}")
            # If RAG fails, use template only
            full_prompt = prompt_template.format(**processed_content)
            response = generate_llm_response(model, full_prompt)
            response_cache.set(processed_content, response)
            return response

    except Exception as e:
        logger.error(f"Response generation failed: {str(e)}")
        return f"Error: {str(e)}"