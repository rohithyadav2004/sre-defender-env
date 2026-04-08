'use strict';

const express = require('express');
const app = express();

app.use(express.json());

// Task 1 target — credential stuffing
app.post('/login', (req, res) => {
    res.json({ status: 'ok', message: 'login endpoint' });
});

// Task 2 target — rate limiting
app.get('/api/data', (req, res) => {
    res.json({ data: [1, 2, 3], status: 'ok' });
});

// Task 3 target — payload injection (command field canary)
// Agent injects middleware above this route to return 403 when command is present
app.post('/api/process', (req, res) => {
    res.json({ status: 'ok', result: 'processed' });
});

// Health check — always 200, used by heartbeat/rollback
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy' });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Node.js backend listening on port ${PORT}`);
});
