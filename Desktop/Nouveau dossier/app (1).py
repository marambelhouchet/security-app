from flask import Flask, render_template, request, jsonify
import ollama
import pandas as pd
import json
import PyPDF2
import io

app = Flask(__name__)

AVAILABLE_MODELS = ["mistral:latest", "qwen2.5:3b",
                    "deepseek-r1:1.5b", "llama3.2:1b"]

# function for extracting text from different file formats


def extract_text_from_file(file, file_extension):
    text = ""

    try:
        if file_extension == "pdf":
            reader = PyPDF2.PdfReader(file)
            text = "\n".join([page.extract_text()
                             for page in reader.pages if page.extract_text()])

        elif file_extension in {"csv", "xls", "xlsx"}:
            df = pd.read_csv(
                file) if file_extension == "csv" else pd.read_excel(file)
            text = df.to_string(index=False)

        elif file_extension == "json":
            file.seek(0)  # Reset file pointer
            text = json.dumps(json.load(file), indent=2)

    except Exception as e:
        return f"Error extracting text: {str(e)}"

    return text.strip()


@app.route('/')
def index():
    return render_template('index.html', models=AVAILABLE_MODELS)


@app.route('/generate', methods=['POST'])
def generate():
    prompt = request.form.get("prompt", "").strip()
    model = request.form.get("model", "mistral:latest")

    if not prompt:
        return jsonify({"error": "Prompt is required"}), 400

    file = request.files.get("file")
    extracted_text = ""

    if file and file.filename:
        allowed_extensions = {"pdf", "csv", "json", "xls", "xlsx"}
        file_extension = file.filename.rsplit('.', 1)[-1].lower()

        if file_extension not in allowed_extensions:
            return jsonify({"error": "Invalid file format"}), 400

        # Extract text without saving the file
        extracted_text = extract_text_from_file(
            io.BytesIO(file.read()), file_extension)

    # Combine extracted text with user prompt
    final_prompt = f"{extracted_text}\n\n{prompt}" if extracted_text else prompt

    response = ollama.chat(model=model, messages=[
        {"role": "user", "content": final_prompt}
    ])

    return jsonify({
        "response": response['message']['content']
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)

