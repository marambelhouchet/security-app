import logging  # For logging errors, warnings, and debug information
import re  # For regular expressions (used for cleaning response text)
from dotenv import load_dotenv  # For loading environment variables from a .env file
import requests  # For making HTTP requests to the LLM API
from vectordb import mongo_collection  # MongoDB collection for retrieving recommendations

# Load environment variables from a .env file
load_dotenv()

# Define the list of available models
AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]

# Initialize logging configuration
logging.basicConfig(level=logging.INFO)

# Function to retrieve context from MongoDB based on alert type, gravity, and language
def retrieve_context(alert_text: str, alert_type: str, gravity: str, language: str = "en") -> str:
    """
    Retrieve context using alert type, gravity, and language filters.

    Parameters:
        alert_text (str): The raw alert text (not used in this implementation).
        alert_type (str): The type of alert (e.g., "SubscribedPower").
        gravity (str): The severity level of the alert (e.g., "High", "Moderate", "Low").
        language (str): The language for the context ("en" for English, "fr" for French).

    Returns:
        str: A formatted string containing recommendations or an error message.
    """
    try:
        # Define alert type mappings for English and French
        alert_type_mapping_en = {
            "SubscribedPower": "SubscribedPower",
            "CurrentDayVsLastDay": "CurrentDayVsLastDay",
            "CosphiThreshold": "CosphiThreshold",
            "ElectricityCuts": "ElectricityCuts",
            "WeekThreshold": "WeekThreshold",
            "ExceededThreshold": "ExceededThreshold"
        }

        alert_type_mapping_fr = {
            "SubscribedPower": "Puissance Souscrite Dépassée",
            "CurrentDayVsLastDay": "Évolution Journalière vs Jour Précédent",
            "CosphiThreshold": "Seuil du Cos φ Dépassé",
            "ElectricityCuts": "Coupures d’Électricité",
            "WeekThreshold": "Alerte de Consommation Hebdomadaire",
            "ExceededThreshold": "Seuil de THDV Dépassé"
        }

        # Select the appropriate mapping based on the language
        if language == "fr":
            normalized_alert_type = alert_type_mapping_fr.get(alert_type, alert_type)
        else:
            normalized_alert_type = alert_type_mapping_en.get(alert_type, alert_type)

        logging.info(f"Retrieving context for alert_type='{normalized_alert_type}', gravity='{gravity}', language='{language}'")

        # Build the MongoDB query to retrieve recommendations
        query = {
            "gravity": {"$regex": f"^{gravity}$", "$options": "i"},  # Match gravity case-insensitively
            "problem": {"$regex": normalized_alert_type, "$options": "i"}  # Match alert type case-insensitively
        }
        logging.debug(f"MongoDB query: {query}")

        # Execute the query on the MongoDB collection
        result = mongo_collection.find_one(query)
        logging.debug(f"MongoDB result: {result}")

        # If no result is found, return a warning message
        if not result:
            logging.warning(f"No matching recommendations found for gravity='{gravity}' and alert_type='{normalized_alert_type}'.")
            return (
                f"No recommendations found for alert type '{normalized_alert_type}' with gravity '{gravity}'. "
                "Please ensure the database is correctly populated."
            )

        # Extract relevant fields from the MongoDB result
        immediate_actions = result.get("immediate_actions", [])
        recommended_next_steps = result.get("recommended_next_steps", [])
        recommended_actions = result.get("recommended_actions_if_the_issue_persists", [])

        # Log the extracted fields
        logging.info(f"Immediate Actions: {immediate_actions}")
        logging.info(f"Recommended Next Steps: {recommended_next_steps}")
        logging.info(f"Recommended Actions if the Issue Persists: {recommended_actions}")

        # Build the recommendations string dynamically based on available fields
        recommendations = ""

        if immediate_actions:
            recommendations += "Immediate Actions:\n- " + "\n- ".join(immediate_actions) + "\n\n"
        if recommended_next_steps:
            recommendations += "Recommended Next Steps:\n- " + "\n- ".join(recommended_next_steps) + "\n\n"
        if recommended_actions:
            recommendations += "Recommended Actions if the Issue Persists:\n- " + "\n- ".join(recommended_actions) + "\n\n"

        # If no recommendations are available, return a default message
        if not recommendations.strip():
            return "No relevant recommendations available."

        logging.info("Recommendations successfully retrieved and formatted.")
        return recommendations.strip()

    except Exception as e:
        logging.error(f"Context retrieval failed: {str(e)}")
        return "Error retrieving recommendations."

# Function to generate a response using an LLM and MongoDB recommendations
def generate_response(model: str, prompt: str, file_content: str, alert_type: str, gravity: str) -> str:
    """
    Generate LLM response with gravity context and MongoDB recommendations.

    Parameters:
        model (str): The name of the LLM model to use.
        prompt (str): The base prompt to send to the LLM.
        file_content (str): The content of the uploaded file.
        alert_type (str): The type of alert.
        gravity (str): The severity level of the alert.

    Returns:
        str: The generated response text.
    """
    try:
        # Validate if the model is available
        if model not in AVAILABLE_MODELS:
            raise ValueError(f"Model '{model}' not available")

        # Retrieve context with recommendations from MongoDB
        rag_context = retrieve_context(file_content, alert_type, gravity)

        # Check if recommendations exist in the context
        if "No relevant recommendations found." not in rag_context:
            # Extract immediate actions and recommended actions from the context
            immediate_actions_start = rag_context.find("Immediate Actions:")
            recommended_actions_start = rag_context.find("Recommended Actions if the Issue Persists:")

            immediate_actions = rag_context[immediate_actions_start:recommended_actions_start].strip()
            recommended_actions = rag_context[recommended_actions_start:].strip()

            # Build the full prompt with recommendations
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

        # Send the prompt to the LLM API
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

        # Parse the response and clean it for DeepSeek models
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