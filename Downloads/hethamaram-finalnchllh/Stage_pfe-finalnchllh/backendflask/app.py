import os
import re
import json
import logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from ETL import process_alert_data, process_file  # Corrected import
from promptengineering import get_alert_prompt
from cag import generate_response
from mailsending import extract_alert_info, send_alert_email

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Verify email configuration
print("Email Configuration:")
print(f"SMTP_EMAIL: {os.getenv('SMTP_EMAIL')}")
print(f"EMAIL_RECIPIENTS: {os.getenv('EMAIL_RECIPIENTS')}")

app = Flask(__name__)
CORS(app, resources={
    r"/chat": {
        "origins": ["http://localhost:5173", "http://127.0.0.1:5173"],
        "methods": ["POST"],
        "allow_headers": ["Content-Type"]
    }
}, supports_credentials=True)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

AVAILABLE_MODELS = ["qwen2.5:3b", "mistral:latest", "deepseek-r1:1.5b", 
                   "llama3.2:1b", "qwen2-math:1.5b", "qwen2-math:latest"]

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
        file = request.files.get('file')
        if not file:
            return jsonify({"error": "No file uploaded"}), 400
        if file.filename == '':
            return jsonify({"error": "Empty file name"}), 400
        if not file.filename.endswith('.json'):
            return jsonify({"error": "Only JSON files are supported"}), 400

        # Get form data
        language = request.form.get('language', 'en').lower()
        frontend_model = request.form.get('model', 'mistral:latest')

        # Model validation
        backend_model = MODEL_MAPPING.get(frontend_model)
        if not backend_model or backend_model not in AVAILABLE_MODELS:
            return jsonify({"error": f"Model '{frontend_model}' not available"}), 400

        # Process emails with improved parsing
        try:
            emails = request.form.get('emails', '')
            logging.info(f"Received emails from interface: {emails}")
            
            # Split emails by comma if it's a string
            if isinstance(emails, str):
                emails = [e.strip() for e in emails.split(',') if e.strip()]
            
            # Validate each email
            valid_emails = [email for email in emails if is_valid_email(email)]
            
            if not valid_emails:
                logging.warning("No valid emails from interface, using default recipients")
                valid_emails = os.getenv('EMAIL_RECIPIENTS', '').split(',')
            
            logging.info(f"Valid emails for sending: {valid_emails}")
            
        except Exception as e:
            logging.error(f"Email processing error: {str(e)}")
            valid_emails = os.getenv('EMAIL_RECIPIENTS', '').split(',')

        # File processing
        try:
            content = file.read()
            json.loads(content.decode('utf-8'))
            file.seek(0)
            alerts, alerts_by_type = process_file(file, language)
        except (ValueError, RuntimeError) as e:
            logging.error(f"File processing error: {str(e)}")
            return jsonify({"error": f"File processing failed: {str(e)}"}), 400

        all_responses = []
        email_errors = []

        # Process alerts by type
        for alert_type, type_alerts in alerts_by_type.items():
            type_responses = []
            
            # Process each alert individually
            for alert in type_alerts:
                _, gravity, alert_content = alert
                
                try:
                    prompt_config = get_alert_prompt(alert_type, backend_model)
                    if not prompt_config:
                        type_responses.append({"error": f"Unsupported alert type: {alert_type}"})
                        continue

                    response = generate_response(
                        model=backend_model,
                        processed_content=alert_content,
                        alert_type=alert_type,
                        gravity=gravity,
                        language=language
                    ) or "No response generated"

                    alert_response = {
                        "response": response,
                        "metadata": {
                            "alert_type": alert_type,
                            "gravity": gravity,
                            "model": backend_model,
                            "language": language,
                            "processed_data": alert_content
                        }
                    }
                    type_responses.append(alert_response)

                    # Enhanced email sending with better logging
                    if valid_emails:
                        try:
                            logging.info(f"Sending alert to interface-provided emails: {valid_emails}")
                            email_content = response
                            email_result = send_alert_email(
                                subject=f"WattNow Alert - {alert_type}",
                                content=email_content,
                                recipients=valid_emails,
                                lang=language
                            )
                            
                            if email_result:
                                print(f"✅ Email sent to interface-provided address: {valid_emails}")
                            else:
                                print(f"❌ Email sending failed for: {valid_emails}")
                                
                        except Exception as e:
                            error_msg = f"Email sending failed: {str(e)}"
                            print(f"❌ {error_msg}")
                            logging.error(error_msg)
                            email_errors.append(error_msg)

                except Exception as e:
                    logging.error(f"Error processing alert: {str(e)}")
                    type_responses.append({"error": f"Processing failed: {str(e)}"})

            all_responses.extend(type_responses)

        response_data = {
            "alerts": all_responses,
            "processed_count": len(alerts),
            "success_count": len([r for r in all_responses if 'error' not in r]),
            "alert_types": list(alerts_by_type.keys())
        }

        if email_errors:
            response_data["email_errors"] = email_errors

        return jsonify(response_data)

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004, debug=True)
