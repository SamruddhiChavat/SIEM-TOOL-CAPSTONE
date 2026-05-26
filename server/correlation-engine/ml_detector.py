"""
SecureWatch Correlation Engine — ML Anomaly Detector

Lightweight anomaly detection using scikit-learn IsolationForest.
Detects anomalies in: login frequency, bytes transferred, process
spawn rate per agent over sliding time windows.
"""

import os
import json
import time
import pickle
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path

import redis
import numpy as np
from loguru import logger

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("scikit-learn not installed — ML anomaly detection disabled")


class MLAnomalyDetector:
    """
    Uses IsolationForest to detect anomalous agent behavior patterns.
    Features tracked per agent per hour:
      - login_count: number of authentication events
      - bytes_transferred: total network bytes
      - process_spawns: number of new processes
    """

    MODEL_DIR = "/app/models"
    WINDOW_SECONDS = 3600  # 1 hour feature windows
    MIN_SAMPLES = 48       # Minimum hours of data before training (2 days)
    CONTAMINATION = 0.05   # Expected anomaly rate

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.models: Dict[str, IsolationForest] = {}
        self._feature_buffer: Dict[str, Dict[str, float]] = {}

        try:
            self.redis = redis.from_url(redis_url, decode_responses=True)
            self.redis.ping()
        except Exception as e:
            logger.warning(f"Redis unavailable for ML: {e}")
            self.redis = None

        # Load cached models
        self._load_models()

    def update_features(self, agent_id: str, event: Dict[str, Any]) -> None:
        """Update feature counters for the current time window."""
        if not self.redis:
            return

        window_key = self._current_window_key(agent_id)

        try:
            pipe = self.redis.pipeline()

            module = event.get("module", "")

            # Login count
            if "auth" in module or "login" in module or event.get("event_id") in ("4624", "4625"):
                pipe.hincrby(window_key, "login_count", 1)

            # Bytes transferred
            bytes_val = event.get("bytes_sent", 0) + event.get("bytes_recv", 0)
            if bytes_val > 0:
                pipe.hincrbyfloat(window_key, "bytes_transferred", bytes_val)

            # Process spawns
            if "process" in module:
                pipe.hincrby(window_key, "process_spawns", 1)

            pipe.expire(window_key, 8 * 24 * 3600)  # 8 day retention
            pipe.execute()
        except Exception as e:
            logger.debug(f"ML feature update error: {e}")

    def detect_anomaly(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """
        Run anomaly detection on the current window's features.
        Returns anomaly info dict if anomalous, None otherwise.
        """
        if not ML_AVAILABLE or not self.redis:
            return None

        model = self.models.get(agent_id)
        if model is None:
            # Try to train model if we have enough data
            self._train_model(agent_id)
            model = self.models.get(agent_id)
            if model is None:
                return None

        # Get current features
        features = self._get_current_features(agent_id)
        if features is None:
            return None

        try:
            X = np.array([features])
            prediction = model.predict(X)
            score = model.score_samples(X)[0]

            if prediction[0] == -1:  # Anomaly
                return {
                    "type": "ml_anomaly",
                    "agent_id": agent_id,
                    "anomaly_score": round(float(score), 4),
                    "features": {
                        "login_count": features[0],
                        "bytes_transferred": features[1],
                        "process_spawns": features[2],
                    },
                    "severity": "high" if score < -0.5 else "medium",
                    "description": (
                        f"Anomalous behavior detected on agent {agent_id}: "
                        f"logins={features[0]}, bytes={features[1]:.0f}, "
                        f"processes={features[2]} (score={score:.4f})"
                    ),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
        except Exception as e:
            logger.error(f"ML prediction error for {agent_id}: {e}")

        return None

    # ─── Model Training ──────────────────────────────────

    def _train_model(self, agent_id: str) -> None:
        """Train IsolationForest on historical feature data."""
        if not ML_AVAILABLE or not self.redis:
            return

        try:
            # Collect historical windows
            pattern = f"ml:features:{agent_id}:*"
            keys = list(self.redis.scan_iter(pattern, count=200))

            if len(keys) < self.MIN_SAMPLES:
                return

            samples = []
            for key in keys:
                data = self.redis.hgetall(key)
                if data:
                    samples.append([
                        float(data.get("login_count", 0)),
                        float(data.get("bytes_transferred", 0)),
                        float(data.get("process_spawns", 0)),
                    ])

            if len(samples) < self.MIN_SAMPLES:
                return

            X = np.array(samples)
            model = IsolationForest(
                contamination=self.CONTAMINATION,
                n_estimators=100,
                random_state=42,
                n_jobs=1,
            )
            model.fit(X)
            self.models[agent_id] = model

            # Save model
            self._save_model(agent_id, model)
            logger.info(f"ML model trained for agent {agent_id} ({len(samples)} samples)")

        except Exception as e:
            logger.error(f"ML training error for {agent_id}: {e}")

    # ─── Persistence ─────────────────────────────────────

    def _save_model(self, agent_id: str, model) -> None:
        try:
            os.makedirs(self.MODEL_DIR, exist_ok=True)
            path = os.path.join(self.MODEL_DIR, f"{agent_id}.pkl")
            with open(path, "wb") as f:
                pickle.dump(model, f)
        except Exception as e:
            logger.debug(f"Model save error: {e}")

    def _load_models(self) -> None:
        if not os.path.isdir(self.MODEL_DIR):
            return
        for fname in os.listdir(self.MODEL_DIR):
            if fname.endswith(".pkl"):
                agent_id = fname[:-4]
                try:
                    with open(os.path.join(self.MODEL_DIR, fname), "rb") as f:
                        self.models[agent_id] = pickle.load(f)
                    logger.debug(f"Loaded ML model for agent {agent_id}")
                except Exception:
                    pass

    # ─── Helpers ─────────────────────────────────────────

    def _current_window_key(self, agent_id: str) -> str:
        hour = int(time.time() // self.WINDOW_SECONDS)
        return f"ml:features:{agent_id}:{hour}"

    def _get_current_features(self, agent_id: str) -> Optional[List[float]]:
        key = self._current_window_key(agent_id)
        try:
            data = self.redis.hgetall(key)
            if not data:
                return None
            return [
                float(data.get("login_count", 0)),
                float(data.get("bytes_transferred", 0)),
                float(data.get("process_spawns", 0)),
            ]
        except Exception:
            return None
