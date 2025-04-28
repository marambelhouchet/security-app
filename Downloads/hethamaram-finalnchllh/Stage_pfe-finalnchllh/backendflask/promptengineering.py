import json
import logging
import os

# Constants
MAPPING_FILE = 'alert_type_mapping.json'

def initialize_default_mapping():
    """Create initial alert type mapping with default values"""
    default_mapping = {
        "Weekly Consumption Alert": "weekly_threshold",
        "WeekThreshold": "weekly_threshold",
        "THDV": "thdv",
        "ExceededThreshold": "thdv",
        "SubscribedPower": "subscribed_power",
        "Subscribed Power Exceeded": "subscribed_power",
        "This Day vs Last Day Alert": "daily_comparison",
        "CurrentDayVsLastDay": "daily_comparison",
        "Power Factor - Cos Phi": "cosphi",
        "CosphiThreshold": "cosphi",
        "Inactive Device": "electricity_cuts",
        "ElectricityCuts": "electricity_cuts",
        "ThisWeekVsLastWeek": "weekly_threshold"
    }
    return default_mapping

def load_mapping():
    """Load alert type mapping from JSON file or create with defaults if not exists"""
    try:
        if os.path.exists(MAPPING_FILE):
            with open(MAPPING_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # File doesn't exist, create it with default mapping
        default_mapping = initialize_default_mapping()
        with open(MAPPING_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_mapping, f, indent=2)
        logging.info(f"Created new mapping file: {MAPPING_FILE}")
        return default_mapping
        
    except Exception as e:
        logging.error(f"Error managing mapping file: {e}")
        return initialize_default_mapping()  # Fallback to default mapping

def save_mapping(mapping):
    """Save the alert type mapping to JSON file"""
    try:
        with open(MAPPING_FILE, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error saving mapping: {e}")
        return False

# Initialize mapping from file or create new
alert_type_to_filename = load_mapping()

def read_prompt_from_file(lang: str, filename: str) -> str:
    """Read prompt content from a file in the specified language directory.
    
    Args:
        lang (str): Language code ('en' or 'fr')
        filename (str): Name of the prompt file without extension
        
    Returns:
        str: Content of the prompt file or empty string if file not found
    """
    try:
        file_path = os.path.join("prompts", lang, f"{filename}.txt")
        if not os.path.exists(file_path):
            logging.error(f"Prompt file not found: {file_path}")
            return ""
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if content.startswith('# TODO:'):
                logging.warning(f"Using untranslated prompt for {filename} in {lang}")
            return content
    except Exception as e:
        logging.error(f"Error reading prompt file {filename} for {lang}: {str(e)}")
        return ""

def get_alert_prompt(alert_type: str, model: str, alert_data: dict = None) -> dict:
    """Return predefined prompts for alert types by reading from corresponding txt files."""
    # Try to get from mapping or use alert_type directly as filename
    filename = alert_type_to_filename.get(alert_type) or alert_type.lower().replace(' ', '_').replace('-', '_')
    
    # Get requested language from alert_data or default to English
    lang = alert_data.get('language', 'en') if alert_data else 'en'
    
    # Read only the requested language prompt
    prompt = read_prompt_from_file(lang, filename)
    
    # Return dict with only the requested language
    return {lang: prompt}

def add_new_alert_type(type_name: str, prompt_content: str, language: str) -> bool:
    """Add a new alert type and its prompt file."""
    try:
        # Convert type name to filename format
        filename = type_name.lower().replace(' ', '_').replace('-', '_')
        
        # Create prompt file only for the requested language
        prompt_dir = os.path.join("prompts", language)
        os.makedirs(prompt_dir, exist_ok=True)
        
        file_path = os.path.join(prompt_dir, f"{filename}.txt")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(prompt_content)
        
        # Update and persist the mapping
        alert_type_to_filename[type_name] = filename
        if not save_mapping(alert_type_to_filename):
            raise Exception("Failed to save alert type mapping")
        
        logging.info(f"Successfully added new alert type: {type_name} in {language}")
        return True
    except Exception as e:
        logging.error(f"Error adding new alert type: {str(e)}")
        return False