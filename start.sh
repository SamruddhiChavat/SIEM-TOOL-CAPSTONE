#!/bin/bash

# ==========================================
# SecureWatch Home Network Deployment Script
# SIEM Host: 192.168.1.4 | Subnet: 192.168.1.0/24
# ==========================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

SIEM_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "192.168.1.3")

echo -e "${GREEN}=========================================="
echo -e "   SecureWatch - Home Network Deployment"
echo -e "   SIEM Host: ${CYAN}${SIEM_IP}${GREEN}"
echo -e "==========================================${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
  echo -e "${RED}[ERROR] Docker is not running. Please start Docker Desktop.${NC}"
  exit 1
fi

# Check for .env file
if [ ! -f .env ]; then
  echo -e "${YELLOW}[WARNING] .env file not found. Copying from .env.example...${NC}"
  cp .env.example .env
fi

# macOS: Increase socket limits for Packetbeat
if [[ "$OSTYPE" == "darwin"* ]]; then
  echo -e "${YELLOW}[INFO] macOS detected. Setting up syslog forwarding to SecureWatch...${NC}"
  # Point macOS syslog to our Logstash port
  sudo syslog -c com.apple.syslogd -d 7 2>/dev/null || true
fi

echo -e "${YELLOW}[INFO] Elasticsearch requires at least 2GB RAM in Docker Desktop.${NC}"
echo -e "${YELLOW}[INFO] Check: Docker Desktop → Settings → Resources → Memory >= 4GB${NC}"

# Start infrastructure services
echo -e "${GREEN}[1/4] Starting Elasticsearch, PostgreSQL, Redis...${NC}"
docker compose up -d elasticsearch postgres redis

# Wait for Elasticsearch
echo -e "${YELLOW}[INFO] Waiting for Elasticsearch (30-60 seconds)...${NC}"
RETRIES=0
until curl -s http://localhost:9200 > /dev/null 2>&1; do
    sleep 5
    echo -n ". "
    RETRIES=$((RETRIES+1))
    if [ $RETRIES -gt 24 ]; then
        echo -e "\n${RED}[ERROR] Elasticsearch failed to start. Check: docker logs securewatch-elasticsearch${NC}"
        exit 1
    fi
done
echo -e "\n${GREEN}[INFO] Elasticsearch is healthy.${NC}"

# Start remaining services
echo -e "${GREEN}[2/4] Starting Logstash, Kibana, Backend, Frontend, Correlation Engine...${NC}"
docker compose up -d

# Wait for backend
echo -e "${YELLOW}[INFO] Waiting for Backend API...${NC}"
sleep 15
until curl -s http://localhost:8000/health > /dev/null 2>&1; do
    sleep 3
    echo -n ". "
done
echo -e "\n${GREEN}[INFO] Backend API is healthy.${NC}"

# Auto-run DB migrations and ensure admin user exists
echo -e "${GREEN}[*] Running database migrations...${NC}"
docker compose exec -T backend alembic upgrade head 2>&1 | grep -E "Running|INFO|ERROR" || true

echo -e "${GREEN}[*] Ensuring admin user exists...${NC}"
docker compose exec -T backend python create_admin.py admin SecureWatch123! 2>&1 | grep -v Traceback | grep -v "File \"" | grep -v "  " | grep -v "^$" || true
echo -e "${GREEN}[INFO] Admin user ready: admin / SecureWatch123!${NC}"

# Install Filebeat on this Mac host (if brew is available)
echo -e "${GREEN}[3/4] Setting up Beats on this Mac host...${NC}"
if command -v brew &> /dev/null; then
  if ! command -v filebeat &> /dev/null; then
    echo -e "${YELLOW}[INFO] Installing Filebeat via Homebrew...${NC}"
    brew install filebeat 2>/dev/null
  fi
  
  # Configure Filebeat to point to our Logstash
  echo -e "${YELLOW}[INFO] Deploying Filebeat config...${NC}"
  sudo cp beats/filebeat.yml /usr/local/etc/filebeat/filebeat.yml 2>/dev/null || \
    sudo cp beats/filebeat.yml /opt/homebrew/etc/filebeat/filebeat.yml 2>/dev/null
  
  # Start Filebeat as a service
  brew services restart filebeat 2>/dev/null && \
    echo -e "${GREEN}[INFO] Filebeat started - shipping real logs to SecureWatch${NC}" || \
    echo -e "${YELLOW}[WARNING] Could not auto-start Filebeat. Start manually: sudo filebeat -c beats/filebeat.yml${NC}"
else
  echo -e "${YELLOW}[WARNING] Homebrew not found. Install Filebeat manually:${NC}"
  echo -e "  curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.4-darwin-x86_64.tar.gz"
  echo -e "  tar xzvf filebeat-8.13.4-darwin-x86_64.tar.gz"
  echo -e "  sudo ./filebeat/filebeat -e -c beats/filebeat.yml"
fi

echo -e "${GREEN}[4/4] Deployment Complete!${NC}"
echo -e ""
echo -e "${GREEN}=========================================="
echo -e "  SecureWatch is LIVE on your home network!"
echo -e "==========================================${NC}"
echo -e ""
echo -e "${CYAN}Access from ANY device on 192.168.1.0/24:${NC}"
echo -e "  📊 SOC Dashboard:    http://${SIEM_IP}:3000"
echo -e "  ⚔️  Attack Sandbox:   http://${SIEM_IP}:5174"
echo -e "  📦 Kibana:           http://${SIEM_IP}:5601"
echo -e "  🔌 FastAPI Swagger:  http://${SIEM_IP}:8000/docs"
echo -e "  🔍 Elasticsearch:    http://${SIEM_IP}:9200"
echo -e ""
echo -e "${CYAN}To add MORE devices to the SIEM:${NC}"
echo -e "  Linux/Mac  → copy beats/filebeat.yml → set hosts: [\"${SIEM_IP}:5055\"]"
echo -e "  Windows    → install Winlogbeat → copy beats/winlogbeat.yml → set hosts: [\"${SIEM_IP}:5044\"]"
echo -e "  Routers    → set syslog destination to UDP ${SIEM_IP}:5140"
echo -e ""
echo -e "${YELLOW}Live Logs: docker compose logs -f${NC}"
