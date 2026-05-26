const { MAX_LOGS } = require('../config/constants');

class LogStore {
  constructor() {
    this.logs = [];
    this.cursor = 0;
    this.sseClients = new Set();
  }

  addLog(entry) {
    if (this.logs.length >= MAX_LOGS) {
      this.logs.shift();
    }
    this.logs.push(entry);
    this.broadcast(entry);
  }

  getLogsSince(since, limit = 200) {
    return this.logs.filter(l => l.cursor > since).slice(-limit);
  }

  getStats() {
    return {
      total: this.logs.length,
      critical: this.logs.filter(l => l.severity === 'critical').length,
      high: this.logs.filter(l => l.severity === 'high').length,
      blocked: this.logs.filter(l => l.action === 'Blocked').length,
      attacks: this.logs.filter(l => l.source === 'sandbox' && l.severity !== 'info').length,
      cursor: this.cursor,
      sseClients: this.sseClients.size
    };
  }

  clear() {
    this.logs.length = 0;
    this.cursor = 0;
    this.broadcast({ __clear: true });
  }

  addClient(res) {
    this.sseClients.add(res);
  }

  removeClient(res) {
    this.sseClients.delete(res);
  }

  broadcast(entry) {
    const data = `data: ${JSON.stringify(entry)}\n\n`;
    for (const res of this.sseClients) {
      try { res.write(data); } catch (_) { this.removeClient(res); }
    }
  }
}

module.exports = new LogStore();
