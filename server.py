"""
Hook — local Flask server.

Serves the dashboard UI and exposes a POST /analyze endpoint that the
browser calls when the user clicks "Analyze".

Usage:
    python server.py          # http://localhost:5000
    PORT=8080 python server.py
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request, send_from_directory

from hook import HookDetector, HookError

app = Flask(__name__, static_folder=".")
detector = HookDetector()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    email_text: str = data.get("email", "").strip()

    if not email_text:
        return jsonify({"error": "No email content provided."}), 400

    try:
        result = detector.analyze(email_text)
        payload = result.model_dump()
        # Flatten tactics into the top-level payload for easy JS access
        payload["tactics"] = result.tactics.model_dump()
        return jsonify(payload)

    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except HookError as exc:
        return jsonify({"error": f"Analysis failed: {exc}"}), 502
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Unexpected error: {exc}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Hook dashboard → http://localhost:{port}")
    app.run(debug=True, port=port)
