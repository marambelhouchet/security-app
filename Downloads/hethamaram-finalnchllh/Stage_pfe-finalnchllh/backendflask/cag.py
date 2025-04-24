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
        logger.info(f"Starting response generation for {alert_type} (Model: {model}, Language: {language})")
        logger.debug(f"Processed content: {json.dumps(processed_content, indent=2)}")

        if model not in AVAILABLE_MODELS:
            logger.error(f"Invalid model selected: {model}")
            raise ValueError(f"Model '{model}' not available")

        # Check cache first
        logger.info("Checking response cache...")
        cached_response = response_cache.get(processed_content)
        if cached_response:
            logger.info(f"Cache hit for alert_type={alert_type}")
            logger.info(f"Cached response preview: {cached_response[:200]}...")
            return cached_response
        logger.info("Cache miss - generating new response")

        # Get prompt template
        logger.info(f"Getting prompt template for {alert_type}")
        prompt_config = get_alert_prompt(alert_type, model)
        if not prompt_config:
            logger.error(f"No prompt template found for alert_type: {alert_type}")
            raise ValueError(f"No prompt template found for alert_type: {alert_type}")

        prompt_template = prompt_config.get(language, prompt_config.get('en'))
        if not prompt_template:
            logger.error(f"No template found for language: {language}")
            raise ValueError(f"No template found for language: {language}")
        logger.info(f"Using {language} template")

        try:
            # Try RAG first
            logger.info(f"Attempting RAG retrieval for {alert_type} with gravity={gravity}")
            rag_context = retrieve_context(alert_type, gravity, language)
            logger.debug(f"RAG context length: {len(rag_context) if rag_context else 0}")
            
            # Check if RAG was successful and returned valid recommendations
            if (rag_context and 
                "No recommendations available." not in rag_context and 
                "No specific recommendations" not in rag_context and
                "No high-confidence recommendations" not in rag_context):
                
                logger.info(f"RAG successful for alert_type={alert_type}")
                logger.debug(f"RAG context preview: {rag_context[:200]}...")
                
                # Remove recommendation section from template
                logger.info("Removing recommendation sections from template")
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
                
                cleaned_template = prompt_template
                for pattern in patterns:
                    cleaned_template = re.sub(pattern, '', cleaned_template, flags=re.DOTALL | re.IGNORECASE)
                logger.debug(f"Template length after cleaning: {len(cleaned_template)}")
                
                # Format prompt with processed content
                logger.info("Formatting prompt with processed content")
                formatted_prompt = cleaned_template.format(**processed_content)
                
                # Add RAG recommendations
                full_prompt = f"{formatted_prompt.strip()}{rag_context}"
                logger.info("Using RAG recommendations")
                logger.debug(f"Final prompt length: {len(full_prompt)}")
            else:
                # RAG failed or no recommendations found - use complete original template
                logger.info("RAG unsuccessful or no recommendations found - using complete original template")
                formatted_prompt = prompt_template.format(**processed_content)
                full_prompt = formatted_prompt
                logger.debug(f"Using complete original template (length: {len(full_prompt)})")

            # Generate response
            logger.info(f"Generating response using {model}")
            response = generate_llm_response(model, full_prompt)
            logger.info(f"Response generated (length: {len(response)})")
            
            # Cache the response
            logger.info("Caching new response")
            response_cache.set(processed_content, response)
            logger.info(f"New response preview: {response[:200]}...")
            
            return response

        except Exception as e:
            logger.error(f"RAG retrieval error: {str(e)}", exc_info=True)
            logger.info("Falling back to complete original template")
            full_prompt = prompt_template.format(**processed_content)
            response = generate_llm_response(model, full_prompt)
            response_cache.set(processed_content, response)
            return response

    except Exception as e:
        logger.error(f"Response generation failed: {str(e)}", exc_info=True)
        return f"Error: {str(e)}"