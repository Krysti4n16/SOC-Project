#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SOC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${GREEN}Stopping SOC Lab${NC}"

pkill -f "log_collector.py"
pkill -f "detection_engine.py"
pkill -f "osquery_monitor.py"
pkill -f "suricata_monitor.py"
pkill -f "active_response.py"

if [ -f /tmp/suricata.pid ]; then
    sudo kill $(cat /tmp/suricata.pid) 2>/dev/null
    sudo rm /tmp/suricata.pid
fi

echo -e "${YELLOW}Cleaning up Terminal windows...${NC}"
osascript -e 'tell application "Terminal" to close (every window whose name contains "SOC-")'

echo -e "${YELLOW}Shutting down ELK Stack${NC}"
docker compose -f "$SOC_DIR/docker-compose.yml" down

echo -e "${GREEN}SOC Lab stopped successfully${NC}"