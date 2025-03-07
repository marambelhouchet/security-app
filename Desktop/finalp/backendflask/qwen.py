import os
import json
import ollama
import pandas as pd
import pdfplumber
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

conversation_history = []
def extract_text_from_pdf(file_path):
    text = ""
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text()
    return text

def extract_text_from_excel(file_path):
    df = pd.read_excel(file_path)
    return df.to_string()

def extract_text_from_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return json.dumps(data, indent=4)  

@app.route("/chat", methods=["POST"])
def chat():
    user_message = None
    uploaded_file = None

    if request.content_type == 'application/json':
        user_message = request.json.get("message", "")
    elif 'multipart/form-data' in request.content_type:
        user_message = request.form.get("message", "")
        uploaded_file = request.files.get("file")
    else:
        return jsonify({"error": "Unsupported media type"}), 415

    if not user_message and not uploaded_file:
        return jsonify({"error": "No message or file provided"}), 400

    if uploaded_file:
        file_path = os.path.join("uploads", uploaded_file.filename)
        uploaded_file.save(file_path)

        if uploaded_file.filename.endswith(".pdf"):
            file_content = extract_text_from_pdf(file_path)
        elif uploaded_file.filename.endswith((".xlsx", ".xls")):
            file_content = extract_text_from_excel(file_path)
        elif uploaded_file.filename.endswith(".json"):
            file_content = extract_text_from_json(file_path)
        else:
            return jsonify({"error": "Unsupported file type"}), 400

        conversation_history.append({"role": "user", "content": f"Uploaded file content: {file_content}"})

    if user_message:
        conversation_history.append({"role": "user", "content": user_message})

    try:
        response = ollama.chat(model="qwen2.5:3b", messages=conversation_history)
        model_response = response['message']['content']
        conversation_history.append({"role": "assistant", "content": model_response})
        return jsonify({"response": model_response})
    except Exception as e:
        return jsonify({"error": f"Error in Ollama API: {str(e)}"}), 500

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)  
    app.run(debug=True, port=5004)  
