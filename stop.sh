#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo -e "${GREEN}Stopping SecureWatch Ecosystem...${NC}"

docker compose down

echo -e "${GREEN}All systems stopped gracefully.${NC}"
