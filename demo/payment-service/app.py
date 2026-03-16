"""
Payment Service — handles payment processing.
Has a 5% error rate to demonstrate error detection and alerting.
NO instrumentation.
"""
import random
import time
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/api/payments/charge", methods=["POST"])
def charge():
    """Process a payment. Fails ~5% of the time."""
    data = request.get_json(silent=True) or {}
    amount = data.get("amount", 0)
    user_id = data.get("user_id", 0)

    # Simulate processing time: 50-150ms
    time.sleep(random.uniform(0.05, 0.15))

    # 5% error rate — demonstrates alerting
    if random.random() < 0.05:
        return jsonify({
            "error": "payment_declined",
            "message": "Card declined by issuer",
            "user_id": user_id,
        }), 500

    return jsonify({
        "status": "charged",
        "amount": amount,
        "user_id": user_id,
        "transaction_id": f"txn_{random.randint(100000, 999999)}",
    })


@app.route("/api/payments/history", methods=["GET"])
def history():
    """Get payment history."""
    time.sleep(random.uniform(0.02, 0.05))  # 20-50ms

    return jsonify({
        "payments": [
            {"id": f"txn_{i}", "amount": round(random.uniform(10, 200), 2)}
            for i in range(random.randint(3, 10))
        ]
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"service": "payment-service", "status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8004)
