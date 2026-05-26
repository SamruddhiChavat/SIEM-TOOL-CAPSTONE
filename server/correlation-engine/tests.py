import unittest
from engine import CorrelationEngine
from state_manager import StateManager
import time

class MockStateManager:
    def __init__(self):
        self.state = {}
        
    def is_suppressed(self, rule_id, entity_key):
        return False
        
    def suppress_alert(self, rule_id, entity_key, timeframe_seconds=900):
        pass
        
    def track_event(self, threshold_key, event_id, window_seconds):
        if threshold_key not in self.state:
            self.state[threshold_key] = []
        self.state[threshold_key].append(time.time())
        return len(self.state[threshold_key])

class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        self.engine = CorrelationEngine()
        self.engine.state_manager = MockStateManager()
        # Mock the API calls
        class MockAlertGenerator:
            def create_alert(self, rule, event, state_manager):
                return {"alert_id": "TEST-1"}
        self.engine.alert_generator = MockAlertGenerator()
        class MockResponseDispatcher:
            def dispatch(self, alert):
                pass
        self.engine.response_dispatcher = MockResponseDispatcher()
        class MockRiskScorer:
            def update_asset_score(self, alert):
                pass
        self.engine.risk_scorer = MockRiskScorer()
        
    def test_threshold_logic(self):
        rule = {
            "rule_id": "TEST-1",
            "name": "Test Rule",
            "logic": {
                "condition": "threshold",
                "threshold": 3,
                "window": 60,
                "group_by": "source_ip"
            }
        }
        self.engine.rules = [rule]
        
        event1 = {"source_ip": "1.1.1.1", "@timestamp": time.time()}
        event2 = {"source_ip": "1.1.1.1", "@timestamp": time.time()}
        event3 = {"source_ip": "1.1.1.1", "@timestamp": time.time()}
        
        # Test that event 1 does not trigger
        self.engine.evaluate_rules(event1)
        self.assertEqual(len(self.engine.state_manager.state["TEST-1:1.1.1.1"]), 1)
        
        # Test that event 2 does not trigger
        self.engine.evaluate_rules(event2)
        self.assertEqual(len(self.engine.state_manager.state["TEST-1:1.1.1.1"]), 2)
        
        # Test that event 3 triggers
        self.engine.evaluate_rules(event3)
        self.assertEqual(len(self.engine.state_manager.state["TEST-1:1.1.1.1"]), 3)

if __name__ == '__main__':
    unittest.main()
