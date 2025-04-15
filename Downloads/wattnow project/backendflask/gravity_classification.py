import logging  # For logging warnings, errors, and debug information

# Function to safely retrieve a value from a nested dictionary or list
def safe_deep_get(d, path):
    """
    Safely retrieve a value from a nested dictionary using a list of keys.

    Parameters:
        d (dict or list): The nested dictionary or list to retrieve the value from.
        path (list): A list of keys representing the path to the desired value.

    Returns:
        The value at the specified path if it exists, otherwise None.
    """
    try:
        for key in path:
            if isinstance(d, list):
                d = d[0]  # Assume the list contains a single dictionary, retrieve the first element
            if not isinstance(d, dict):
                logging.warning(f"Expected dict, found {type(d)} instead for path {path}")
                return None  # If it's not a dictionary, return None
            d = d.get(key)  # Retrieve the value for the current key
        return d
    except Exception as e:
        logging.error(f"safe_deep_get error for path {path}: {e}")
        return None  # Return None if an error occurs

# Function to determine the gravity of an alert based on structured data
def determine_gravity(alert_type: str, data: dict, language: str = "en") -> str:
    """
    Classify alert gravity based on structured alert data and return localized gravity.

    Parameters:
        alert_type (str): The type of alert (e.g., "SubscribedPower").
        data (dict): The structured alert data.
        language (str): The language for the gravity output ("en" for English, "fr" for French).

    Returns:
        str: The severity level of the alert ("High", "Moderate", "Low").
    """
    try:
        # Define rules for determining gravity based on alert type
        gravity_rules = {
            "Subscribed Power Exceeded": {
                "params": [("type", "details", "percentage"), ("type", "details", "hold_on")],
                "rules": [
                    (lambda p, h: float(p) > 20 and float(h) > 2, "High"),
                    (lambda p, h: 10 <= float(p) <= 20 and float(h) >= 1, "Moderate"),
                    (lambda p, h: float(p) < 10, "Low"),
                    (lambda p, h: True, "Moderate") 
                ]
            },
            "SubscribedPower": {
                "params": [("type", "details", "percentage"), ("type", "details", "hold_on")],
                "rules": [
                    (lambda p, h: float(p) > 20 and float(h) > 2, "High"),
                    (lambda p, h: 10 <= float(p) <= 20 and float(h) >= 1, "Moderate"),
                    (lambda p, h: float(p) < 10, "Low"),
                    (lambda p, h: True, "Moderate") 
                ]
            },
            "ThisWeekVsLastWeek": {
                "params": [("type", "details", "today_consumtion"), ("type", "details", "yesterday_consumption")],
                "rules": [
                    (lambda t, y: (float(t) - float(y)) / float(y) * 100 > 40, "High"),
                    (lambda t, y: 20 <= (float(t) - float(y)) / float(y) * 100 <= 40, "Moderate"),
                    (lambda t, y: (float(t) - float(y)) / float(y) * 100 < 20, "Low")
                ]
            },
            "THDV": {
                "params": [("type", "details", "Value")],
                "rules": [
                    (lambda v: float(v) > 8, "High"),
                    (lambda v: 5 <= float(v) <= 8, "Moderate"),
                    (lambda v: float(v) < 5, "Low")
                ]
            },
            "ExceededThreshold": {
                "params": [("type", "details", "Value")],
                "rules": [
                    (lambda v: float(v) > 8, "High"),
                    (lambda v: 5 <= float(v) <= 8, "Moderate"),
                    (lambda v: float(v) < 5, "Low")
                ]
            },
            "ElectricityCuts": {
                "params": [("type", "details", "hold_on"), ("device", "label")],
                "rules": [
                    (lambda h, l: "critical" in l.lower() and float(h) > 30, "High"),
                    (lambda h, l: "non-critical" in l.lower() and float(h) > 60, "Moderate"),
                    (lambda h, l: float(h) < 30, "Low")
                ]
            },
            "CosphiThreshold": {
                "params": [("type", "details", "Value"), ("device", "label")],
                "rules": [
                    (lambda v, l: (("industrial" in l.lower() and float(v) < 0.7) or 
                                  ("commercial" in l.lower() and float(v) < 0.85)), "High"),
                    (lambda v, l: (("industrial" in l.lower() and 0.7 <= float(v) < 0.8) or 
                                  ("commercial" in l.lower() and 0.85 <= float(v) < 0.9)), "Moderate"),
                    (lambda v, l: float(v) >= 0.9, "Low")
                ]
            },
            "WeekThreshold": {
                "params": [("type", "details", "Value"), ("type", "details", "threshold")],
                "rules": [
                    (lambda v, t: (float(v) - float(t)) / float(t) * 100 > 25, "High"),
                    (lambda v, t: 15 <= (float(v) - float(t)) / float(t) * 100 <= 25, "Moderate"),
                    (lambda v, t: (float(v) - float(t)) / float(t) * 100 < 15, "Low")
                ]
            },
            "CurrentDayVsLastDay": {
                "params": [("type", "details", "Value"), ("type", "details", "threshold")],
                "rules": [
                    (lambda v, t: (float(v) - float(t)) / float(t) * 100 > 25, "High"),
                    (lambda v, t: 15 <= (float(v) - float(t)) / float(t) * 100 <= 25, "Moderate"),
                    (lambda v, t: (float(v) - float(t)) / float(t) * 100 < 15, "Low")
                ]
            },
        }

        # If the alert type is not in the rules, return a default gravity
        if alert_type not in gravity_rules:
            return "undefined type of alert"

        # Extract parameters for the alert type
        params = []
        for param_path in gravity_rules[alert_type]["params"]:
            val = safe_deep_get(data, param_path)  # Retrieve the value using the safe_deep_get function
            if val is None:
                logging.warning(f"Missing or invalid value for path {param_path}, defaulting to 0")
            params.append(val if val is not None else 0)  # Default to 0 if the value is missing

        logging.debug(f"Parameters extracted for {alert_type}: {params}")

        # Evaluate the rules for the alert type
        for rule, gravity in gravity_rules[alert_type]["rules"]:
            try:
                if rule(*params):  # Apply the rule to the extracted parameters
                    # Return localized gravity
                    if language == "fr":
                        return {"High": "Élevée", "Moderate": "Modérée", "Low": "Faible"}[gravity]
                    return gravity
            except Exception as e:
                logging.error(f"Rule evaluation error for {alert_type}: {str(e)}")
                continue

        # Default gravity if no rules match
        return "undefined type of alert" 
    except Exception as e:
        logging.error(f"Gravity determination failed for {alert_type}: {str(e)}")
        return "undefined type of alert"  if language == "en" else "undefined type of alert" 

