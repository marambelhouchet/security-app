import os
import re
from dotenv import load_dotenv
from flask import Flask, request, jsonify  # Flask framework for handling HTTP requests and responses
from flask_cors import CORS
from werkzeug.utils import secure_filename  # Utility for handling file uploads securely
import json  # For working with JSON data
import logging  # For logging errors and information
from ETL import process_file  # Custom function to process uploaded files
from promptengeneering import get_alert_prompt  # Custom function to retrieve prompt templates
from cag import generate_response, ResponseCache  # Custom functions for caching and generating responses
from vectordb import mongo_collection  # MongoDB collection for retrieving recommendations
from mailsending import extract_alert_info
from mailsending import send_alert_email
# Load environment variables first
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/chat": {"origins": os.getenv('FRONTEND_URL', 'http://localhost:3000')}})

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]
MODEL_MAPPING = {
    'Qwen 2.5 (3B)': 'qwen2.5:3b',
    'qwen2-math (7B)': 'qwen2-math:latest',
    'qwen2-math(1.5B)': 'qwen2-math:1.5b',
    'mistral(7B)': 'mistral:latest',
    'deepseek-r1(1.5B)': 'deepseek-r1:1.5b',
    'llama3.2(1B)': 'llama3.2:1b'
}

def is_valid_email(email):
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

@app.route('/chat', methods=['POST'])
def chat_handler():
    try:
        # Model validation
        frontend_model = request.form.get('model', 'mistral:latest')
        backend_model = MODEL_MAPPING.get(frontend_model)
        if not backend_model or backend_model not in AVAILABLE_MODELS:
            return jsonify({"error": f"Model '{frontend_model}' not available"}), 400

        # File validation
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Empty file name"}), 400

        # Email processing
        raw_emails = request.form.get('emails', '')
        clean_emails = raw_emails.replace('[', '').replace(']', '').replace('"', '')
        emails = [e.strip() for e in clean_emails.split(',') if e.strip()]
        valid_emails = [email for email in emails if is_valid_email(email)]

        # File processing
        language = request.form.get('language', 'en').lower()
        try:
            alert_type, gravity, content = process_file(file, language)
        except Exception as e:
            logging.error(f"File processing error: {str(e)}")
            return jsonify({"error": f"File processing failed: {str(e)}"}), 400

        # Alert info extraction
        try:
            alert_data = json.loads(content)
            alert_info = extract_alert_info(alert_data) or {}
        except Exception as e:
            logging.error(f"Alert info extraction failed: {str(e)}")
            return jsonify({"error": "Invalid alert data format"}), 400

        # Prompt generation
        prompt_config = get_alert_prompt(alert_type, backend_model)
        if not prompt_config:
            return jsonify({"error": f"Unsupported alert type: {alert_type}"}), 400
            
        try:
            formatted_prompt = prompt_config.get(language, prompt_config['en']).format(**alert_info)
        except KeyError as e:
            return jsonify({"error": f"Missing data field: {str(e)}"}), 400

        # Generate response
        try:
            response = generate_response(
                model=backend_model,
                prompt=formatted_prompt,
                file_content=content,
                alert_type=alert_type,
                gravity=gravity,
                mongo_collection=mongo_collection
            ) or "No response generated"  # Ensure response is never empty
        except Exception as e:
            logging.error(f"Response generation error: {str(e)}")
            return jsonify({"error": "Response generation failed"}), 500

        # Email sending
        email_error = None
        if valid_emails:
            try:
                send_alert_email(
                    subject=f"WattNow Alert: {alert_type} ({gravity})",
                    content=f"{formatted_prompt}\n\nRecommended Actions:\n{response}",
                    recipients=valid_emails,
                    lang=language
                )
            except Exception as e:
                email_error = str(e)
                logging.error(f"Email error: {email_error}")

        # Build response
        response_data = {
            "response": response,
            "metadata": {
                "alert_type": alert_type,
                "gravity": gravity,
                "model": backend_model,
                "language": language
            }
        }
        if email_error:
            response_data["warning"] = f"Email failed: {email_error}"

        return jsonify(response_data)

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)