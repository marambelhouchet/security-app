import json
from gravity_classification import determine_gravity  # Changed to absolute import

def process_file(file, language="en") -> tuple:
    """
    Process uploaded file to extract alert type, gravity, and content.

    Parameters:
        file: The uploaded file object (e.g., from a Flask request).
        language: The language of the file content (default is "en" for English).

    Returns:
        tuple: A tuple containing:
            - alert_type (str): The type of alert extracted from the file.
            - gravity (str): The severity level of the alert (e.g., "High", "Moderate", "Low").
            - content (str): The raw content of the file as a string.

    Raises:
        ValueError: If the file content is not valid JSON or if the alert type is not found.
        RuntimeError: If any other error occurs during file processing.
    """
    try:
        # Read and decode the file content
        content = file.read().decode('utf-8')
        data = json.loads(content)  # Parse JSON content

        # Extract alert type from JSON structure
        alert_type = data.get('alert_type')

        # Fallback logic to extract alert type if not directly available
        if not alert_type:
            alert_type_value = data.get('type')
            if isinstance(alert_type_value, dict):
                alert_type = alert_type_value.get('type')
            else:
                alert_type = alert_type_value

        # Raise an error if alert type is not found
        if not alert_type:
            raise ValueError("Alert type not found in file content")

        # Determine the gravity of the alert
        gravity = determine_gravity(alert_type, data, language)

        # Return the extracted data
        return alert_type, gravity, content

    except json.JSONDecodeError as e:
        # Handle invalid JSON format
        raise ValueError(f"Invalid JSON format: {str(e)}")
    except Exception as e:
        # Handle any other errors
        raise RuntimeError(f"File processing failed: {str(e)}")

