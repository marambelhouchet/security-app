from flask import Flask, request, jsonify
from flask_cors import CORS
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

MODEL_NAME = "meta-llama/Llama-3.2-1B"

try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    # Add padding token if it does not exist
    if tokenizer.pad_token is None:
        tokenizer.add_special_tokens({'pad_token': tokenizer.eos_token})
    
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float16,
        device_map="auto"
    )
    model.resize_token_embeddings(len(tokenizer))  # Resize embeddings for new tokens
except Exception as e:
    raise RuntimeError(f"Failed to load model: {e}")

@app.route("/", methods=["POST"])
def generate_text():
    try:
        data = request.get_json()
        print(f"Received data: {data}")  # Debugging statement
        prompt = data.get("prompt")
        max_tokens = data.get("max_tokens", 50)

        if not prompt:
            return jsonify({"error": "Missing 'prompt' in request"}), 400

        # Tokenize the input with attention mask
        inputs = tokenizer(prompt, return_tensors="pt", padding=True, truncation=True)
        inputs = inputs.to("cuda" if torch.cuda.is_available() else "cpu")

        # Generate the text
        outputs = model.generate(
            inputs.input_ids,
            attention_mask=inputs.attention_mask,
            max_new_tokens=max_tokens,
            temperature=0.7,
            top_p=0.9,
            do_sample=True,
            pad_token_id=tokenizer.pad_token_id  # Set pad_token_id to pad_token_id
        )

        result = tokenizer.decode(outputs[0], skip_special_tokens=True)
        return jsonify({"input_prompt": prompt, "generated_text": result})
    
    except Exception as e:
        print(f"Error: {e}")  # Debugging statement
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)