const store = require('../models/logStore');
const logService = require('../services/logService');

exports.receiveLog = (req, res) => {
  const entry = logService.processIncomingLog(req.body);
  console.log(`[${entry.severity.toUpperCase()}] ${entry.id} | ${entry.eventType} | ${entry.sourceIp} → ${entry.destIp}`);
  res.status(200).json({ status: 'ok', id: entry.id });
};

exports.streamLogs = (req, res) => {
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const since = parseInt(req.query.since || '0', 10);
  const missed = store.getLogsSince(since, 2000); // Send all missed
  for (const l of missed) {
    res.write(`data: ${JSON.stringify(l)}\n\n`);
  }

  const ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch (_) { clearInterval(ping); store.removeClient(res); }
  }, 15000);

  store.addClient(res);
  console.log(`[SSE] Client connected (${store.sseClients.size} total)`);

  req.on('close', () => {
    clearInterval(ping);
    store.removeClient(res);
    console.log(`[SSE] Client disconnected (${store.sseClients.size} total)`);
  });
};

exports.getLogs = (req, res) => {
  const since  = parseInt(req.query.since || '0',  10);
  const limit  = parseInt(req.query.limit || '200', 10);
  res.json({ logs: store.getLogsSince(since, limit), cursor: store.cursor });
};

exports.getStats = (_req, res) => {
  res.json(store.getStats());
};

exports.clearLogs = (_req, res) => {
  store.clear();
  console.log('[Relay] Log store cleared');
  res.json({ status: 'cleared' });
};
