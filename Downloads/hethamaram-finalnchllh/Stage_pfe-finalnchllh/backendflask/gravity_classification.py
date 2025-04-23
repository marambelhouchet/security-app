import logging

# Function to safely retrieve a value from a nested dictionary or list
def safe_deep_get(d, path):
    try:
        for key in path:
            if isinstance(d, list):
                d = d[0]
            if not isinstance(d, dict):
                logging.warning(f"Expected dict, found {type(d)} instead for path {path}")
                return None
            d = d.get(key)
        return d
    except Exception as e:
        logging.error(f"safe_deep_get error for path {path}: {e}")
        return None

# Function to determine the gravity of an alert based on structured data
def determine_gravity(alert_type: str, data: dict, language: str = "en") -> str:
    try:
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
                "params": [("type", "details", "Value"), ("type", "details", "perviousWeekConsumption")],
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
                    (lambda v, l: ("industrial" in l.lower() and float(v) < 0.7) or 
                                  ("commercial" in l.lower() and float(v) < 0.85), "High"),
                    (lambda v, l: ("industrial" in l.lower() and 0.7 <= float(v) < 0.8) or 
                                  ("commercial" in l.lower() and 0.85 <= float(v) < 0.9), "Moderate"),
                    (lambda v, l: float(v) >= 0.9, "Low"),
                    (lambda v, l: True, "Moderate")  # Default rule
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
            }
        }

        if alert_type not in gravity_rules:
            return "undefined type of alert" if language == "en" else "type d'alerte indéfini"

        try:
            # Extract parameters
            params = []
            for param_path in gravity_rules[alert_type]["params"]:
                val = safe_deep_get(data, param_path)
                if val is None:
                    logging.warning(f"Missing or invalid value for path {param_path} in alert type '{alert_type}', defaulting to 0")
                    if param_path[-1] == "label":  # Default to empty string for labels
                        params.append("")
                    else:
                        params.append(0)  # Default to 0 for numeric values
                elif isinstance(val, str) and param_path[-1] == "label":
                    params.append(val)  # Keep string values for labels
                else:
                    params.append(float(val))  # Convert numeric values to float

            # Evaluate rules
            for rule, gravity in gravity_rules[alert_type]["rules"]:
                try:
                    if rule(*params):
                        return {"High": "Élevée", "Moderate": "Modérée", "Low": "Faible"}[gravity] if language == "fr" else gravity
                except Exception as e:
                    logging.error(f"Rule evaluation error for {alert_type}: {str(e)}")
                    continue
            return "undefined type of alert" if language == "en" else "type d'alerte indéfini"
        except Exception as e:
            logging.error(f"Gravity determination failed for {alert_type}: {str(e)}")
            return "undefined type of alert" if language == "en" else "type d'alerte indéfini"
    except Exception as e:
        logging.error(f"Gravity determination failed for {alert_type}: {str(e)}")
        return "undefined type of alert" if language == "en" else "type d'alerte indéfini"