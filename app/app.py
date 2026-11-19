
import os
import logging

from flask import Flask, request, jsonify, render_template
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.text import tokenizer_from_json
from tensorflow.keras.preprocessing.sequence import pad_sequences

from url_explainer import analyze_url


# --------------------------------------------------
# FLASK CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

logging.basicConfig(level=logging.INFO)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
MODELS_DIR = os.path.join(PROJECT_DIR, "models")

MAX_LEN = 200


# --------------------------------------------------
# LOAD TRAINED MODEL
# --------------------------------------------------

model_path = os.path.join(
    MODELS_DIR,
    "hybrid_phishguard.keras"
)

tokenizer_path = os.path.join(
    MODELS_DIR,
    "tokenizer.json"
)

model = load_model(model_path)

with open(tokenizer_path, "r", encoding="utf-8") as file:
    tokenizer = tokenizer_from_json(file.read())

print("Hybrid CNN-BiLSTM model loaded!")
print("Explainable AI analyzer loaded!")


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# PHISHING DETECTION API
# --------------------------------------------------

@app.route("/predict", methods=["POST"])
def predict():

    try:

        data = request.get_json(silent=True) or {}

        url = data.get("url", "")

        if not isinstance(url, str) or not url.strip():
            return jsonify({
                "error": "Please enter a valid URL."
            }), 400

        url = url.strip().lower()

        if len(url) > 2048:
            return jsonify({
                "error": "URL is too long. Maximum length is 2048 characters."
            }), 400

        # ------------------------------------------
        # 1. HYBRID DEEP LEARNING PREDICTION
        # ------------------------------------------

        sequence = tokenizer.texts_to_sequences([url])

        padded = pad_sequences(
            sequence,
            maxlen=MAX_LEN,
            padding="post",
            truncating="post"
        )

        probability = float(
            model.predict(padded, verbose=0)[0][0]
        )

        prediction = (
            "Phishing"
            if probability >= 0.5
            else "Legitimate"
        )

        confidence = (
            probability
            if prediction == "Phishing"
            else 1 - probability
        ) * 100

        # ------------------------------------------
        # 2. EXPLAINABLE URL ANALYSIS
        # ------------------------------------------

        explanation = analyze_url(url)

        # ------------------------------------------
        # 3. COMBINED API RESPONSE
        # ------------------------------------------

        result = {

            "url": url,

            "prediction": prediction,

            "confidence": round(confidence, 2),

            "phishing_probability": round(
                probability * 100, 2
            ),

            "model": "HYBRID CNN-BILSTM",

            "explanation": {

                "risk_score": explanation["risk_score"],

                "risk_level": explanation["risk_level"],

                "indicators": explanation["indicators"],

                "recommendations": explanation["recommendations"]

            }

        }

        return jsonify(result), 200

    except Exception:

        app.logger.exception("URL prediction failed")

        return jsonify({
            "error": "An internal prediction error occurred."
        }), 500


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.route("/health", methods=["GET"])
def health():

    return jsonify({
        "status": "running",
        "model": "HYBRID CNN-BILSTM",
        "explainable_ai": "enabled"
    })


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
        use_reloader=False
    )
