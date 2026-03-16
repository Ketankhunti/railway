/**
 * User Service — handles user CRUD operations.
 * Calls db-service for data persistence.
 * NO instrumentation, NO OTEL.
 */
const express = require('express');
const http = require('http');

const app = express();
app.use(express.json());

const DB_SERVICE = process.env.DB_SERVICE_URL || 'http://db-service:8003';

// In-memory user data (simulating what db-service would return)
const users = {
  1: { id: 1, name: 'Alice', email: 'alice@example.com' },
  2: { id: 2, name: 'Bob', email: 'bob@example.com' },
  42: { id: 42, name: 'Demo User', email: 'demo@railway.app' },
};

function callDbService(path, callback) {
  const url = new URL(path, DB_SERVICE);
  const options = {
    hostname: url.hostname,
    port: url.port,
    path: url.pathname + url.search,
    headers: { 'Connection': 'close' }, // Disable keep-alive for eBPF CLOSE events
  };
  http.get(options, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      try {
        callback(null, JSON.parse(data), res.statusCode);
      } catch (e) {
        callback(e);
      }
    });
  }).on('error', callback);
}

app.get('/api/users', (req, res) => {
  // Call db-service to "query" users
  callDbService('/internal/db/query?table=users', (err, data, status) => {
    if (err) {
      return res.status(502).json({ error: 'db-service unavailable' });
    }
    res.json(Object.values(users));
  });
});

app.get('/api/users/:id', (req, res) => {
  const user = users[req.params.id];
  if (!user) {
    return res.status(404).json({ error: 'user not found' });
  }

  // Call db-service for the lookup
  callDbService(`/internal/db/query?table=users&id=${req.params.id}`, (err) => {
    if (err) {
      return res.status(502).json({ error: 'db-service unavailable' });
    }
    res.json(user);
  });
});

app.post('/api/users', (req, res) => {
  const id = Object.keys(users).length + 1;
  const user = { id, ...req.body };
  users[id] = user;
  res.status(201).json(user);
});

app.get('/health', (req, res) => {
  res.json({ service: 'user-service', status: 'ok' });
});

const port = process.env.PORT || 8002;
app.listen(port, '0.0.0.0', () => {
  console.log(`user-service listening on :${port}`);
});
