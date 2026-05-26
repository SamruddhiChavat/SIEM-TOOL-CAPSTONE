# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in SecureWatch, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Email the maintainer directly at: **jesalshah27@gmail.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgement** within 48 hours
- **Assessment** within 7 days
- **Fix timeline** communicated within 14 days
- Credit in the security advisory (unless you prefer anonymity)

## Security Considerations

### Default Configuration Warnings

> ⚠️ The default configuration is intended for **local development and learning**. Before deploying to any network-accessible environment:

1. **Enable Elasticsearch security** — Set `xpack.security.enabled=true` in `elasticsearch.yml`
2. **Change all default passwords** in `.env`
3. **Restrict CORS origins** in `backend/main.py`
4. **Enable JWT authentication** on all API endpoints
5. **Use TLS/HTTPS** for all service-to-service communication
6. **Never commit `.env` files** — they are excluded via `.gitignore`

### API Key Management

- VirusTotal and AbuseIPDB API keys are stored in `.env`
- In production, use Docker secrets or a secrets management tool (HashiCorp Vault, AWS Secrets Manager)
- Rotate API keys if you suspect they have been exposed

### Network Exposure

- By default, ports `3000`, `5601`, `8000`, and `9200` are exposed to the host
- In production, only expose the SOC Dashboard (port 3000) and place the backend behind a reverse proxy
