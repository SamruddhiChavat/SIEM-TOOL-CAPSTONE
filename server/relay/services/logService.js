const { randomBytes } = require('crypto');
const { ATTACK_MITRE } = require('../config/constants');
const store = require('../models/logStore');

exports.processIncomingLog = (logData) => {
  const now = new Date().toISOString();
  const rawEventType = (logData.eventType || 'UNKNOWN');
  const eventKey = rawEventType.toUpperCase().replace(/-/g, '_').replace(/ /g, '_');
  const mitre = ATTACK_MITRE[`ATTACK_${eventKey}`] || ATTACK_MITRE[eventKey] || null;
  const severity = (logData.severity || 'info').toLowerCase();

  const entry = {
    id:           `LOG-${Date.now()}-${randomBytes(2).toString('hex')}`,
    timestamp:    now,
    severity:     severity,
    sourceHost:   logData.srcHostname  || logData.srcIp    || 'sandbox',
    sourceIp:     logData.srcIp        || '10.0.0.1',
    destIp:       logData.dstIp        || '',
    destHostname: logData.dstHostname  || '',   // ← forwarded for SOC asset matching
    eventType:    rawEventType,
    category:     mitre ? mitre.name : (severity === 'info' ? 'Network' : 'Attack'),
    message:      logData.message      || `${rawEventType} from ${logData.srcIp}`,
    mitre:        mitre ? mitre.technique : null,
    mitreTactic:  mitre ? mitre.tactic    : null,
    action:       mitre ? 'Blocked'       : 'Logged',
    source:       'sandbox',
    cursor:       ++store.cursor,
  };

  store.addLog(entry);
  return entry;
};
