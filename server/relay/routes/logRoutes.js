const express = require('express');
const router = express.Router();
const logController = require('../controllers/logController');

router.post('/logs', logController.receiveLog);
router.get('/logs/stream', logController.streamLogs);
router.get('/logs', logController.getLogs);
router.get('/stats', logController.getStats);
router.delete('/logs', logController.clearLogs);

module.exports = router;
