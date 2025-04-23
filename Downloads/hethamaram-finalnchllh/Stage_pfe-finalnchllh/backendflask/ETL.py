import json
import logging
from gravity_classification import determine_gravity  # Ensure this import is correct

def process_file(file, language="en") -> tuple:
    """
    Process JSON file and return tuple of (alerts_list, alerts_by_type)
    """
    try:
        content = file.read().decode('utf-8')
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {str(e)}")

        alerts = []
        alerts_by_type = {}

        # Handle both single alert and array of alerts
        if isinstance(data, list):
            alert_list = data
        elif isinstance(data, dict):
            alert_list = [data]
        else:
            raise ValueError("Invalid JSON format - must be object or array")

        # Process each alert
        for alert_data in alert_list:
            if not isinstance(alert_data, dict):
                logging.warning("Skipping invalid alert data format")
                continue

            # Process alert and get type
            alert_type = get_alert_type(alert_data)
            if not alert_type:
                logging.warning("Skipping alert with missing type")
                continue

            # Process the alert
            try:
                gravity = determine_gravity(alert_type, alert_data, language)
                processed_content = process_alert_content(alert_type, alert_data)

                if processed_content is not None:
                    alert_tuple = (alert_type, gravity, processed_content)
                    alerts.append(alert_tuple)
                    
                    # Group by alert type
                    if alert_type not in alerts_by_type:
                        alerts_by_type[alert_type] = []
                    alerts_by_type[alert_type].append(alert_tuple)

            except Exception as e:
                logging.error(f"Failed to process alert {alert_type}: {str(e)}")

        if not alerts:
            raise ValueError("No valid alerts found in file content")

        return alerts, alerts_by_type

    except Exception as e:
        logging.error(f"File processing failed: {str(e)}")
        raise RuntimeError(f"File processing failed: {str(e)}")

def get_alert_type(alert_data):
    """Extract alert type from alert data"""
    alert_type = alert_data.get('alert_type')
    if not alert_type:
        alert_type_value = alert_data.get('type')
        if isinstance(alert_type_value, dict):
            alert_type = alert_type_value.get('type')
        else:
            alert_type = alert_type_value
    return alert_type

def calculate_percent(value, threshold):
    """Helper to calculate percentage difference, avoiding division by zero."""
    try:
        # Convert string inputs to float
        value = float(value) if value is not None else None
        threshold = float(threshold) if threshold is not None else None
        
        if value is None or threshold is None or threshold == 0:
            return 0  # Return 0 instead of None for better handling
        
        return round(((value - threshold) / threshold) * 100, 2)
    except (ValueError, TypeError) as e:
        logging.error(f"Error calculating percentage: {str(e)}")
        return 0  # Return 0 on conversion errors

def process_alert_content(alert_type, alert_data):
    """
    Process alert content based on alert type and return processed data dictionary.
    """
    try:
        type_details = alert_data.get('type', {}).get('details', {})
        processed = {
            'device': {'label': alert_data.get('device', {}).get('label', 'Unknown Device')},
            'unit': alert_data.get('unit') or type_details.get('unit', 'kWh'),
            'percentage': alert_data.get('percentage') or type_details.get('percentage', '0'),
            'Value': alert_data.get('Value') or type_details.get('Value', '0'),
            'detectedAt': alert_data.get('detectedAt') or type_details.get('detectedAt', 'Unknown Timestamp'),
            'threshold': alert_data.get('threshold') or type_details.get('threshold', '0'),
        }

        if alert_type == 'SubscribedPower':
            value = float(processed.get('Value', 0))
            threshold = float(processed.get('threshold', 0))
            processed.update({
                'hold_on': alert_data.get('hold_on'),
                'overrun_pct': calculate_percent(value, threshold)
            })

        elif alert_type == 'ThisWeekVsLastWeek':
            processed.update({
                'type': {'type': alert_data.get('type', {}).get('type')},
                'previousWeekConsumption': alert_data.get('previousWeekConsumption'),
                'weekly_variation_percent': calculate_percent(
                    alert_data.get('Value'), 
                    alert_data.get('threshold')
                )
            })

        elif alert_type == 'WeekThreshold':
            processed.update({
                'endDate': {'day': alert_data.get('endDate', {}).get('day')},
                'startDate': {'day': alert_data.get('startDate', {}).get('day')},
                'thresholdType': alert_data.get('thresholdType'),
                'weekly_variation_percent': calculate_percent(
                    alert_data.get('Value'), 
                    alert_data.get('threshold')
                )
            })

        elif alert_type == 'CosphiThreshold':
            processed.update({
                'overrun_pct': calculate_percent(
                    alert_data.get('Value'), 
                    alert_data.get('threshold')
                )
            })

        elif alert_type == 'ExceededThreshold':
            processed.update({
                'measure': alert_data.get('measure'),
                'overrun_pct': calculate_percent(
                    alert_data.get('Value'), 
                    alert_data.get('threshold')
                )
            })

        elif alert_type == 'ElectricityCuts':
            processed.update({
                'hold_on': alert_data.get('hold_on')
            })

        elif alert_type == 'CurrentDayVsLastDay':
            yesterday_str = (
                type_details.get('yesterday_consumption')
                or type_details.get('yesterday_consumtion')
                or alert_data.get('yesterday_consumption')
                or alert_data.get('yesterday_consumtion')
                or '0'
            )
            today_str = (
                type_details.get('today_consumption')
                or type_details.get('today_consumtion')
                or alert_data.get('today_consumption')
                or alert_data.get('today_consumtion')
                or '0'
            )
            
            try:
                today_val = float(today_str)
                yesterday_val = float(yesterday_str)
            except ValueError as e:
                logging.error(f"Failed to convert consumption values to float: {str(e)}")
                today_val = yesterday_val = 0

            processed.update({
                'yesterday_consumption': yesterday_str,
                'today_consumption': today_str,
                'variation_percent': calculate_percent(today_val, yesterday_val)
            })

        processed['original_alert_data'] = alert_data
        return processed

    except Exception as e:
        logging.error(f"Error processing {alert_type} alert: {str(e)}")
        return None

def process_alert_data(alerts_list, alert_data, language):
    """
    Process individual alert data and append to alerts list.
    
    Args:
        alerts_list (list): List to append processed alerts to
        alert_data (dict): Raw alert data to process
        language (str): Language for processing
    """
    alert_type = get_alert_type(alert_data)
    if not alert_type:
        logging.warning("Skipping alert with missing type")
        return

    try:
        gravity = determine_gravity(alert_type, alert_data, language)
        processed_content = process_alert_content(alert_type, alert_data)

        if processed_content is not None:
            alert_tuple = (alert_type, gravity, processed_content)
            alerts_list.append(alert_tuple)
    except Exception as e:
        logging.error(f"Failed to process alert {alert_type}: {str(e)}")
