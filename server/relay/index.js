const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const logRoutes = require('./routes/logRoutes');
const store = require('./models/logStore');
const { PORT } = require('./config/constants');

const app = express();
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());

app.use('/api', logRoutes);

app.get('/health', (_req, res) => res.json({ status: 'ok', logs: store.logs.length, sseClients: store.sseClients.size }));

app.listen(PORT, () => {
  console.log(`[Relay] Sandbox Relay Server  →  http://localhost:${PORT}`);
  console.log(`[Relay] POST logs  : http://localhost:${PORT}/api/logs`);
  console.log(`[Relay] SSE stream : http://localhost:${PORT}/api/logs/stream`);
  console.log(`[Relay] Stats      : http://localhost:${PORT}/api/stats`);
});
