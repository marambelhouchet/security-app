import logging
import os

def read_prompt_from_file(lang: str, filename: str) -> str:
    """Read the content of a prompt file based on language and filename."""
    file_path = os.path.join("prompts", lang, f"{filename}.txt")
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        logging.error(f"Prompt file not found: {file_path}")
        return ""

def get_alert_prompt(alert_type: str, model: str, alert_data: dict = None) -> dict:
    """Return predefined prompts for alert types by reading from corresponding txt files."""
    alert_type_to_filename = {
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
        "ThisWeekVsLastWeek": "weekly_threshold",
    }
    
    filename = alert_type_to_filename.get(alert_type, "")
    if not filename:
        logging.error(f"No filename mapping for alert type: {alert_type}")
        return {}
    
    # Read base prompts
    prompts = {
        "en": read_prompt_from_file("en", filename),
        "fr": read_prompt_from_file("fr", filename)
    }
    
    # Check for math model (if needed, adjust filename here)
    if model.startswith("qwen2-math:latest"):
        math_filename = f"{filename}_math"
        math_prompts = {
            "en": read_prompt_from_file("en", math_filename),
            "fr": read_prompt_from_file("fr", math_filename)
        }
        # Override base prompts if math prompts exist
        for lang in ["en", "fr"]:
            if math_prompts[lang]:
                prompts[lang] = math_prompts[lang]
    
    return prompts