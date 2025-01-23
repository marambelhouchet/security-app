from flask import Flask, request, jsonify
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from accelerate import load_checkpoint_and_dispatch, disk_offload
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Model name from Hugging Face
MODEL_NAME_11B = "meta-llama/Llama-3.2-11B-Vision"

# Load the tokenizer directly from Hugging Face
tokenizer_11B = AutoTokenizer.from_pretrained(MODEL_NAME_11B)

# Load the model directly from Hugging Face with offloading
model_11B = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME_11B,
    torch_dtype=torch.float16
)

# Use disk offload to handle model weights
offload_path = "offload"  # Directory to offload the weights to disk
model_11B = disk_offload(model_11B, offload_path)

@app.route("/")
def read_root():
    return jsonify({"message": "Welcome to the Llama 3.2 11B API!"})

@app.route("/generate/11B", methods=["POST"])
def generate_text_11B():
    try:
        # Get the input JSON data
        data = request.get_json()

        # Validate the data
        if "prompt" not in data:
            return jsonify({"error": "Missing 'prompt' in request"}), 400

        prompt = data["prompt"]
        max_tokens = data.get("max_tokens", 50)

        # Process the input prompt
        inputs = tokenizer_11B(prompt, return_tensors="pt").to("cuda" if torch.cuda.is_available() else "cpu")

        # Generate text from the model
        outputs = model_11B.generate(
            inputs.input_ids,
            max_new_tokens=max_tokens,
            temperature=0.7,
            top_p=0.9,
            do_sample=True
        )

        result = tokenizer_11B.decode(outputs[0], skip_special_tokens=True)
        return jsonify({"input_prompt": prompt, "generated_text": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)