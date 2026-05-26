# Contributing to SecureWatch

Thank you for your interest in contributing to SecureWatch! This document provides guidelines and instructions to help you contribute effectively.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and professional environment for everyone.

## How to Contribute

### Reporting Bugs

1. Check existing [Issues](https://github.com/JesalShah27/SecureWatch/issues) to avoid duplicates.
2. Use the bug report template and include:
   - Steps to reproduce
   - Expected vs. actual behavior
   - Environment details (OS, Docker version, etc.)
   - Relevant log output (`docker compose logs <service>`)

### Suggesting Features

Open a feature request issue with:
- A clear description of the feature
- The use case it addresses
- Any relevant MITRE ATT&CK technique mappings

### Submitting Changes

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** following the coding standards below
4. **Test thoroughly** — run the attack simulator to verify detection rules
5. **Commit** with clear messages:
   ```bash
   git commit -m "feat(engine): add T1053 scheduled task detection rule"
   ```
6. **Push** and open a Pull Request

### Commit Message Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Use Case |
|--------|----------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation |
| `rule` | New detection rule |
| `refactor` | Code restructuring |
| `test` | Adding tests |
| `ci` | CI/CD changes |

Example: `rule(SIEM-030): add RDP brute force detection for T1021.001`

## Coding Standards

### Python (Backend & Engine)
- Python 3.11+
- Type hints on all function signatures
- Docstrings on all public methods
- Logging via `logging` module (not `print()`)

### React (Frontend)
- Functional components with hooks
- TailwindCSS for styling (use the `siem*` color tokens defined in `tailwind.config.js`)
- Props validation

### Detection Rules (YAML)
- Must include: `rule_id`, `name`, `description`, `mitre_tactic`, `mitre_technique`, `severity`, `logic`, `response_action`, `false_positive_notes`
- Rule IDs follow the pattern `SIEM-XXX`
- Must map to a valid MITRE ATT&CK technique

## Development Setup

```bash
# Clone and configure
git clone https://github.com/JesalShah27/SecureWatch.git
cd SecureWatch/securewatch
cp .env.example .env

# Start the stack
./start.sh

# View logs
docker compose logs -f correlation_engine

# Run the attack simulator for testing
cd attack_simulator && python3 simulator.py
```

## Adding a New Detection Rule

1. Create a YAML file in `correlation_engine/rules/`:
   ```yaml
   rule_id: SIEM-XXX
   name: Your Rule Name
   description: What this detects
   mitre_tactic: Tactic Name
   mitre_technique: TXXXX
   severity: critical|high|medium|low
   logic:
     field: field.path
     condition: equals|contains|exists|threshold
     value: expected_value
   response_action: alert_only|block_ip
   false_positive_notes: "Known benign scenarios"
   ```
2. The engine auto-loads new rules on restart — no code changes needed.
3. Test with the attack simulator.

## Questions?

Open a [Discussion](https://github.com/JesalShah27/SecureWatch/discussions) for questions, ideas, or general conversation.
