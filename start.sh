#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SOC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${GREEN}SOC Lab — Starting all components${NC}"

if ! docker ps > /dev/null 2>&1; then
    echo -e "${RED}Docker is not running — start Docker Desktop first${NC}"
    exit 1
fi

if ! curl -s http://localhost:9200 > /dev/null 2>&1; then
    echo -e "${YELLOW}Starting ELK Stack...${NC}"
    docker compose -f "$SOC_DIR/docker-compose.yml" up -d
    echo -e "${YELLOW}Waiting 30s for Elasticsearch to start${NC}"
    sleep 30
else
    echo -e "${GREEN}ELK Stack already running${NC}"
fi

echo -e "${GREEN}Starting Log Collector...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && source venv/bin/activate && python3 scripts/log_collector.py\") to \"SOC-LogCollector\""
sleep 2

echo -e "${GREEN}Starting Detection Engine...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && source venv/bin/activate && python3 scripts/detection_engine.py\") to \"SOC-Detection\""
sleep 2

echo -e "${GREEN}Starting osquery Monitor...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && source venv/bin/activate && python3 scripts/osquery_monitor.py\") to \"SOC-osquery\""
sleep 2

echo -e "${GREEN}Starting Suricata Monitor...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && source venv/bin/activate && sudo suricata -D -c $SOC_DIR/suricata/suricata.yaml -i en0 --pidfile /tmp/suricata.pid && sleep 2 && python3 scripts/suricata_monitor.py\") to \"SOC-Suricata\""
sleep 2

echo -e "${GREEN}[*] Starting Correlation Engine...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && source venv/bin/activate && python3 scripts/correlation_engine.py\") to \"SOC-Correlation\""
sleep 2

echo -e "${GREEN}Starting Active Response Engine...${NC}"
osascript -e "tell application \"Terminal\" to set custom title of (do script \"cd $SOC_DIR && sudo $SOC_DIR/venv/bin/python3 scripts/active_response.py --auto\") to \"SOC-ActiveResponse\""

echo ""
echo -e "${GREEN}All components started${NC}"
echo -e "${GREEN}Kibana: http://localhost:5601${NC}"
echo ""
echo -e "${YELLOW}To stop all components: ./stop.sh${NC}"