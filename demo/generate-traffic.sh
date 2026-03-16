#!/bin/bash
# Traffic generator for the demo stack.
# Sends a mix of requests to exercise all service paths.

API_GATEWAY=${API_GATEWAY:-http://localhost:8001}
INTERVAL=${INTERVAL:-0.5}  # seconds between requests
COUNT=${COUNT:-100}

echo "Generating $COUNT requests to $API_GATEWAY (interval: ${INTERVAL}s)"

for i in $(seq 1 $COUNT); do
    # Mix of request types
    case $((i % 5)) in
        0)
            # Checkout (exercises full chain: api-gw → user-svc → db-svc + payment-svc)
            curl -s -X POST "$API_GATEWAY/api/checkout" \
                -H "Content-Type: application/json" \
                -d "{\"user_id\": $((i % 3 + 1))}" \
                -o /dev/null -w "POST /api/checkout → %{http_code} (%{time_total}s)\n"
            ;;
        1)
            # List users (api-gw → user-svc → db-svc)
            curl -s "$API_GATEWAY/api/users" \
                -o /dev/null -w "GET  /api/users → %{http_code} (%{time_total}s)\n"
            ;;
        2|3)
            # Get specific user (api-gw → user-svc → db-svc)
            curl -s "$API_GATEWAY/api/users/$((i % 3 + 1))" \
                -o /dev/null -w "GET  /api/users/$((i % 3 + 1)) → %{http_code} (%{time_total}s)\n"
            ;;
        4)
            # Health check (api-gw only)
            curl -s "$API_GATEWAY/health" \
                -o /dev/null -w "GET  /health → %{http_code} (%{time_total}s)\n"
            ;;
    esac

    sleep $INTERVAL
done

echo "Done. Generated $COUNT requests."
