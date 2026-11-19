
from flask import Flask, render_template, request, jsonify
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.preprocessing.text import tokenizer_from_json
import json
import os

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "..", "models")

# Load tokenizer
with open(os.path.join(MODEL_DIR, "tokenizer.json"), "r") as f:
    tokenizer = tokenizer_from_json(f.read())

MAX_LEN = 200

# Load trained models
models = {
    "cnn": load_model(os.path.join(MODEL_DIR, "cnn_phishguard.keras")),
    "bilstm": load_model(os.path.join(MODEL_DIR, "bilstm_phishguard.keras")),
    "hybrid": load_model(os.path.join(MODEL_DIR, "hybrid_phishguard.keras"))
}

print("All PhishGuard AI models loaded successfully!")

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}

        url = str(data.get("url", "")).strip().lower()
        model_name = str(data.get("model", "hybrid")).lower()

        if not url:
            return jsonify({"error": "Please enter a URL"}), 400

        if model_name not in models:
            return jsonify({"error": "Invalid model selected"}), 400

        # Convert URL into character sequence
        sequence = tokenizer.texts_to_sequences([url])
        padded = pad_sequences(
            sequence,
            maxlen=MAX_LEN,
            padding="post",
            truncating="post"
        )

        # Predict
        probability = float(
            models[model_name].predict(padded, verbose=0)[0][0]
        )

        if probability >= 0.5:
            prediction = "Phishing"
            confidence = probability * 100
        else:
            prediction = "Legitimate"
            confidence = (1 - probability) * 100

        return jsonify({
            "prediction": prediction,
            "confidence": round(confidence, 2),
            "model": model_name.upper()
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
