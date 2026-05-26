import redis
import json
import logging
import os

logger = logging.getLogger(__name__)

class StateManager:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        try:
            self.client = redis.from_url(redis_url)
            self.client.ping()
            logger.info("Connected to Redis for state management.")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.client = None

    def is_suppressed(self, rule_id, entity_key):
        """Check if an alert for this rule/entity was recently fired to avoid spam."""
        if not self.client:
            return False
            
        suppression_key = f"suppress:{rule_id}:{entity_key}"
        return self.client.exists(suppression_key)

    def suppress_alert(self, rule_id, entity_key, timeframe_seconds=900):
        """Suppress future alerts for this rule + entity for timeframe (default 15m)"""
        if not self.client:
            return
            
        suppression_key = f"suppress:{rule_id}:{entity_key}"
        self.client.setex(suppression_key, timeframe_seconds, "suppressed")
    
    def track_event(self, threshold_key, event_id, window_seconds):
        """For sliding window thresholds (e.g. 5 fails in 2 minutes)"""
        if not self.client:
            return 1
            
        tracker_key = f"threshold:{threshold_key}"
        
        # Add event to sorted set with timestamp as score
        import time
        now = time.time()
        
        # Use pipeline for atomicity
        pipe = self.client.pipeline()
        pipe.zadd(tracker_key, {event_id: now})
        # Remove events older than the window
        pipe.zremrangebyscore(tracker_key, 0, now - window_seconds)
        # Update expiry on the key
        pipe.expire(tracker_key, window_seconds)
        # Count remaining
        pipe.zcard(tracker_key)
        
        results = pipe.execute()
        count = results[-1]
        return count
