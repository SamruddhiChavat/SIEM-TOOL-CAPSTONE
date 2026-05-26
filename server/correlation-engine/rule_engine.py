"""
SecureWatch Correlation Engine — Advanced Rule Engine

Supports threshold rules, sequence detection, composite boolean logic,
suppression windows, rule groups, and priority-based evaluation.
Replaces the basic pattern matcher in the original engine.
"""

import time
import re
from typing import Dict, Any, List, Optional
from loguru import logger


class RuleEvaluator:
    """
    Advanced rule evaluation engine supporting multiple rule types
    beyond simple field matching.
    """

    def __init__(self, state_manager):
        self.state_manager = state_manager
        self._suppression_cache: Dict[str, float] = {}

    def evaluate(self, event: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """
        Evaluate a single event against a rule definition.
        Returns True if the rule fires.
        """
        logic = rule.get("logic", {})
        rule_type = logic.get("type", logic.get("condition", "equals"))

        # Check suppression window first
        if self._is_suppressed(rule, event):
            return False

        # Dispatch to appropriate evaluator
        evaluators = {
            "equals": self._eval_equals,
            "contains": self._eval_contains,
            "regex": self._eval_regex,
            "exists": self._eval_exists,
            "threshold": self._eval_threshold,
            "sequence": self._eval_sequence,
            "composite": self._eval_composite,
            "frequency": self._eval_threshold,  # alias
            "not_equals": self._eval_not_equals,
            "greater_than": self._eval_greater_than,
            "less_than": self._eval_less_than,
        }

        evaluator = evaluators.get(rule_type, self._eval_equals)

        try:
            matched = evaluator(event, logic)
        except Exception as e:
            logger.error(f"Rule evaluation error for {rule.get('rule_id', '?')}: {e}")
            return False

        if matched:
            # Apply suppression window
            suppression = rule.get("suppression", logic.get("suppression", 0))
            if suppression > 0:
                self._apply_suppression(rule, event, suppression)

        return matched

    # ─── Evaluators ──────────────────────────────────────

    def _eval_equals(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        return field_val == logic.get("value")

    def _eval_not_equals(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        return field_val is not None and field_val != logic.get("value")

    def _eval_contains(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        if field_val is None:
            return False
        return logic.get("value", "") in str(field_val)

    def _eval_regex(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        if field_val is None:
            return False
        pattern = logic.get("pattern", logic.get("value", ""))
        try:
            return bool(re.search(pattern, str(field_val), re.IGNORECASE))
        except re.error:
            return False

    def _eval_exists(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        return field_val is not None and field_val != ""

    def _eval_greater_than(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        try:
            return float(field_val) > float(logic.get("value", 0))
        except (TypeError, ValueError):
            return False

    def _eval_less_than(self, event: Dict, logic: Dict) -> bool:
        field_val = self._get_field(event, logic.get("field", ""))
        try:
            return float(field_val) < float(logic.get("value", 0))
        except (TypeError, ValueError):
            return False

    def _eval_threshold(self, event: Dict, logic: Dict) -> bool:
        """
        Threshold/frequency rule: fires when N events matching a condition
        occur within T seconds, grouped by a field.
        """
        # Check base field condition first
        field = logic.get("field", "")
        value = logic.get("match_value", logic.get("value", ""))
        condition = logic.get("match_condition", "equals" if value else "exists")

        if field:
            field_val = self._get_field(event, field)
            if condition == "equals" and field_val != value:
                return False
            elif condition == "contains" and value not in str(field_val or ""):
                return False
            elif condition == "exists" and field_val is None:
                return False

        # Track in state manager
        group_by = logic.get("group_by", "source_ip")
        entity = self._get_field(event, group_by) or "unknown"
        threshold = logic.get("threshold", 5)
        window = logic.get("window", 120)

        rule_id = logic.get("_rule_id", "unknown")
        count = self.state_manager.track_event(
            threshold_key=f"{rule_id}:{entity}",
            event_id=str(event.get("@timestamp", time.time())),
            window_seconds=window
        )

        return count >= threshold

    def _eval_sequence(self, event: Dict, logic: Dict) -> bool:
        """
        Sequence rule: fires when event A is followed by event B
        within T seconds from the same entity.
        """
        steps = logic.get("steps", [])
        if not steps:
            return False

        group_by = logic.get("group_by", "source_ip")
        entity = self._get_field(event, group_by) or "unknown"
        window = logic.get("window", 300)
        rule_id = logic.get("_rule_id", "unknown")

        # Check which step this event matches
        for i, step in enumerate(steps):
            step_field = step.get("field", "")
            step_value = step.get("value", "")
            step_condition = step.get("condition", "equals")

            field_val = self._get_field(event, step_field)
            matches = False

            if step_condition == "equals" and field_val == step_value:
                matches = True
            elif step_condition == "contains" and step_value in str(field_val or ""):
                matches = True
            elif step_condition == "exists" and field_val is not None:
                matches = True

            if matches:
                seq_key = f"seq:{rule_id}:{entity}"
                current_step = self.state_manager.get_sequence_step(seq_key)

                if i == 0:
                    # First step matched — start sequence
                    self.state_manager.set_sequence_step(seq_key, 1, window)
                elif i == current_step:
                    # Next step in sequence
                    if i == len(steps) - 1:
                        # Final step — sequence complete
                        self.state_manager.clear_sequence(seq_key)
                        return True
                    else:
                        self.state_manager.set_sequence_step(seq_key, i + 1, window)

        return False

    def _eval_composite(self, event: Dict, logic: Dict) -> bool:
        """
        Composite rule: evaluates AND/OR conditions across multiple fields.
        """
        operator = logic.get("operator", "AND").upper()
        conditions = logic.get("conditions", [])

        if not conditions:
            return False

        results = []
        for cond in conditions:
            field_val = self._get_field(event, cond.get("field", ""))
            cond_type = cond.get("condition", "equals")
            cond_value = cond.get("value", "")

            if cond_type == "equals":
                results.append(field_val == cond_value)
            elif cond_type == "contains":
                results.append(cond_value in str(field_val or ""))
            elif cond_type == "regex":
                try:
                    results.append(bool(re.search(cond_value, str(field_val or ""), re.IGNORECASE)))
                except re.error:
                    results.append(False)
            elif cond_type == "exists":
                results.append(field_val is not None and field_val != "")
            elif cond_type == "not_equals":
                results.append(field_val != cond_value)

        if operator == "AND":
            return all(results)
        elif operator == "OR":
            return any(results)

        return False

    # ─── Suppression ─────────────────────────────────────

    def _is_suppressed(self, rule: Dict, event: Dict) -> bool:
        """Check if this rule is currently in a suppression window."""
        rule_id = rule.get("rule_id", "")
        group_by = rule.get("logic", {}).get("group_by", "source_ip")
        entity = self._get_field(event, group_by) or "global"
        key = f"suppress:{rule_id}:{entity}"

        last_fired = self._suppression_cache.get(key, 0)
        return time.time() - last_fired < rule.get("suppression", 0)

    def _apply_suppression(self, rule: Dict, event: Dict, duration: int) -> None:
        """Apply suppression window after a rule fires."""
        rule_id = rule.get("rule_id", "")
        group_by = rule.get("logic", {}).get("group_by", "source_ip")
        entity = self._get_field(event, group_by) or "global"
        key = f"suppress:{rule_id}:{entity}"
        self._suppression_cache[key] = time.time()

    # ─── Helpers ─────────────────────────────────────────

    @staticmethod
    def _get_field(data: Dict, key_path: str) -> Any:
        """Get nested field value using dot notation."""
        if not key_path:
            return None
        keys = key_path.split('.')
        val = data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return None
        return val
