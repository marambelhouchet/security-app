import hashlib
import json
import time
from collections import OrderedDict
import re
from threading import Lock
import logging
from chromadb import logger
import requests
from promptengineering import get_alert_prompt
from rag import retrieve_context
from ETL import save_processed_data

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

class RecommendationCache:
    """CAG implementation specifically for recommendations based on alert type + gravity"""
    def __init__(self, max_size=200):
        self.max_size = max_size
        self.cache = OrderedDict()  # {key: (recommendations, timestamp)}
        self.lock = Lock()
        self.logger = logging.getLogger("CAG")

    def generate_key(self, alert_type: str, gravity: str) -> str:
        """Generate composite key from alert type and gravity"""
        try:
            composite = f"{alert_type.lower()}-{gravity.lower()}"
            return hashlib.sha256(composite.encode()).hexdigest()
        except Exception as e:
            self.logger.error(f"Key generation error: {str(e)}")
            return None

    def get(self, alert_type: str, gravity: str) -> str | None:
        """Get cached recommendations for alert type and gravity combination"""
        key = self.generate_key(alert_type, gravity)
        if not key:
            return None

        with self.lock:
            if key in self.cache:
                recommendations, _ = self.cache[key]
                self.cache.move_to_end(key)
                self.logger.info(f"CAG hit for {alert_type} ({gravity})")
                return recommendations
            return None

    def set(self, alert_type: str, gravity: str, recommendations: str) -> None:
        """Cache new recommendations with timestamp"""
        key = self.generate_key(alert_type, gravity)
        if not key:
            return

        with self.lock:
            self.cache[key] = (recommendations, time.time())
            self.cache.move_to_end(key)
            if len(self.cache) > self.max_size:
                self.cache.popitem(last=False)

# Initialize both caches
response_cache = ResponseCache(max_size=500)
recommendation_cache = RecommendationCache(max_size=200)

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
        logger.info(f"Starting response generation for {alert_type} (Model: {model}, Language: {language})")
        
        # Check response cache first
        cached_response = response_cache.get(processed_content)
        if cached_response:
            return cached_response

        # Process data and get template
        processed_data_file = save_processed_data(processed_content, alert_type)
        if not processed_data_file:
            raise ValueError("Failed to save processed data")
            
        with open(processed_data_file, 'r', encoding='utf-8') as f:
            structured_data = json.load(f)
            
        prompt_config = get_alert_prompt(alert_type, model)
        if not prompt_config or language not in prompt_config:
            raise ValueError(f"Missing template configuration")

        prompt_template = prompt_config[language]

        # Try CAG first for recommendations
        recommendations = recommendation_cache.get(alert_type, gravity)
        
        if recommendations:
            logger.info("Using CAG recommendations")
            base_prompt = clean_template(prompt_template, remove_recommendations=True)
            formatted_prompt = base_prompt.format(**structured_data['data'])
            full_prompt = (
                f"{formatted_prompt}\n\n"
                f"Structured Data:\n{json.dumps(structured_data, indent=2)}\n\n"
                f"Previous Similar Cases Recommendations:\n{recommendations}"
            )
        else:
            # Fallback to RAG if no cached recommendations
            try:
                rag_context = retrieve_context(alert_type, gravity, language)
                
                if rag_context and not any(x in rag_context for x in [
                    "No recommendations available",
                    "No specific recommendations",
                    "No structured recommendations"
                ]):
                    logger.info("Using RAG recommendations")
                    recommendation_cache.set(alert_type, gravity, rag_context)
                    base_prompt = clean_template(prompt_template, remove_recommendations=True)
                    formatted_prompt = base_prompt.format(**structured_data['data'])
                    full_prompt = (
                        f"{formatted_prompt}\n\n"
                        f"Structured Data:\n{json.dumps(structured_data, indent=2)}\n\n"
                        f"Recommendations:\n{rag_context}"
                    )
                else:
                    logger.info("Using template without external recommendations")
                    formatted_prompt = prompt_template.format(**structured_data['data'])
                    full_prompt = (
                        f"{formatted_prompt}\n\n"
                        f"Structured Data:\n{json.dumps(structured_data, indent=2)}"
                    )
            except Exception as e:
                logger.error(f"RAG error: {str(e)}")
                formatted_prompt = prompt_template.format(**structured_data['data'])
                full_prompt = (
                    f"{formatted_prompt}\n\n"
                    f"Structured Data:\n{json.dumps(structured_data, indent=2)}"
                )

        # Generate and cache response
        response = generate_llm_response(model, full_prompt)
        
        if response and not response.startswith("Error"):
            response_cache.set(processed_content, response)
            return response
        else:
            raise ValueError(f"LLM error: {response}")

    except Exception as e:
        logger.error(f"Response generation failed: {str(e)}")
        return f"Error: {str(e)}"

def clean_template(template: str, remove_recommendations: bool = True) -> str:
    """Clean template by removing specified sections."""
    if not remove_recommendations:
        return template
        
    patterns = [
        r'\*\*Actions recommandées\*\*:.*?(?=\n\n|$)',
                    r'\*\*Recommended Actions\*\*:.*?(?=\n\n|$)',
                    r'\*\*Immediate Actions\*\*:.*?(?=\n\n|$)',
                    r'\*\*Actions Immédiates\*\*:.*?(?=\n\n|$)',
                    r'\*\*Actions immédiates\*\*:.*?(?=\n\n|$)',
                    r'Actions Immédiates:.*?(?=\n\n|$)',
                    r'Immediate Actions:.*?(?=\n\n|$)',
                    r'\*\*Actions\*\*:.*?(?=\n\n|$)',
                    r'\*\*recommendations\*\*:.*?(?=\n\n|$)',
                    r'Recommandations:.*?(?=\n\n|$)',
                    r'2\.\s*\*\*recommendations\*\*:.*?(?=\n\n|$)',
                    r'2\.\s*\*\*Recommendations\*\*:.*?(?=\n\n|$)'
    ]
    
    cleaned = template
    for pattern in patterns:
        cleaned = re.sub(pattern, '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    return cleaned.strip()