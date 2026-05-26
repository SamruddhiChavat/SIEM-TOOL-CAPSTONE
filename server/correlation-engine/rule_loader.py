import os
import yaml
import logging

logger = logging.getLogger(__name__)

class RuleLoader:
    def __init__(self, rules_dir='rules'):
        self.rules_dir = rules_dir
        self.rules = []
        self.load_rules()

    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            logger.warning(f"Rules directory {self.rules_dir} does not exist.")
            return

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith('.yml') or file.endswith('.yaml'):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            rule = yaml.safe_load(f)
                            if self._validate_rule(rule, filepath):
                                self.rules.append(rule)
                    except Exception as e:
                        logger.error(f"Failed to load rule {filepath}: {e}")
        
        logger.info(f"Successfully loaded {len(self.rules)} rules.")

    def _validate_rule(self, rule, filepath):
        required_keys = ['rule_id', 'name', 'severity', 'mitre_tactic', 'logic']
        for key in required_keys:
            if key not in rule:
                logger.error(f"Rule in {filepath} is missing required key '{key}'")
                return False
        return True

    def get_rules(self):
        return self.rules
