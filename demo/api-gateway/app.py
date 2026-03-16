"""
API Gateway — entry point for the demo.
Routes requests to user-service and payment-service.
NO instrumentation, NO OTEL, NO tracing SDK.
"""
import os
import random
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

USER_SERVICE = os.environ.get("USER_SERVICE_URL", "http://user-service:8002")
PAYMENT_SERVICE = os.environ.get("PAYMENT_SERVICE_URL", "http://payment-service:8004")

# Disable keep-alive so each request creates a new TCP connection.
# This ensures eBPF captures CONNECT→SEND→RECV→CLOSE per request.
SESSION = requests.Session()
SESSION.headers.update({"Connection": "close"})


@app.route("/api/checkout", methods=["POST"])
def checkout():
    """Simulates a checkout: fetch user, then charge payment."""
    user_id = request.json.get("user_id", 42) if request.is_json else 42

    # Call user-service
    user_resp = SESSION.get(f"{USER_SERVICE}/api/users/{user_id}", timeout=5)
    if user_resp.status_code != 200:
        return jsonify({"error": "user not found"}), 404

    user = user_resp.json()

    # Call payment-service
    pay_resp = SESSION.post(
        f"{PAYMENT_SERVICE}/api/payments/charge",
        json={"user_id": user_id, "amount": 99.99},
        timeout=5,
    )

    return jsonify({
        "status": "completed" if pay_resp.status_code == 200 else "failed",
        "user": user,
        "payment": pay_resp.json(),
    }), 200 if pay_resp.status_code == 200 else 500


@app.route("/api/users", methods=["GET"])
def list_users():
    """Proxy to user-service."""
    resp = SESSION.get(f"{USER_SERVICE}/api/users", timeout=5)
    return jsonify(resp.json()), resp.status_code


@app.route("/api/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    """Proxy to user-service."""
    resp = SESSION.get(f"{USER_SERVICE}/api/users/{user_id}", timeout=5)
    return jsonify(resp.json()), resp.status_code


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"service": "api-gateway", "status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8001)
