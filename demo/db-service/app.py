"""
DB Service — mock database backend.
Returns canned data. Simulates occasional slow queries.
NO instrumentation.
"""
import random
import time
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/internal/db/query", methods=["GET"])
def query():
    """Simulate a database query with variable latency."""
    table = request.args.get("table", "unknown")
    record_id = request.args.get("id")

    # Simulate query latency: 2-10ms normally, occasional 100-500ms spike
    if random.random() < 0.05:
        time.sleep(random.uniform(0.1, 0.5))  # 5% chance of slow query
    else:
        time.sleep(random.uniform(0.002, 0.01))

    return jsonify({
        "table": table,
        "id": record_id,
        "rows_returned": 1 if record_id else random.randint(5, 50),
        "query_time_ms": random.uniform(1, 10),
    })


@app.route("/internal/db/insert", methods=["POST"])
def insert():
    """Simulate a database insert."""
    time.sleep(random.uniform(0.005, 0.02))  # 5-20ms

    return jsonify({
        "status": "inserted",
        "id": random.randint(1000, 9999),
    }), 201


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"service": "db-service", "status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003)
