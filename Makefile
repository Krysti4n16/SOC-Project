.PHONY: help start stop restart logs build test clean status sigma

# Kolory
GREEN  = \033[0;32m
YELLOW = \033[1;33m
RED    = \033[0;31m
NC     = \033[0m

help:
	@echo ""
	@echo "SOC Lab — Available commands:"
	@echo ""
	@echo "  $(GREEN)make start$(NC)       Start all SOC components"
	@echo "  $(GREEN)make stop$(NC)        Stop all components"
	@echo "  $(GREEN)make restart$(NC)     Restart all components"
	@echo "  $(GREEN)make build$(NC)       Rebuild Docker images"
	@echo "  $(GREEN)make logs$(NC)        Show logs from all containers"
	@echo "  $(GREEN)make status$(NC)      Show status of all containers"
	@echo "  $(GREEN)make test$(NC)        Run all tests"
	@echo "  $(GREEN)make clean$(NC)       Remove containers and volumes"
	@echo "  $(GREEN)make sigma$(NC)       Convert SIGMA rules to ES queries"
	@echo "  $(GREEN)make kibana$(NC)      Open Kibana in browser"
	@echo ""

start:
	@echo "$(GREEN)[*] Starting SOC Lab (Docker + macOS Agents)$(NC)"
	./start.sh
	@make status

stop:
	@echo "$(YELLOW)[*] Stopping SOC Lab$(NC)"
	./stop.sh
	@echo "$(GREEN)[+] Stopped$(NC)"

restart:
	@make stop
	@sleep 3
	@make start

build:
	@echo "$(GREEN)[*] Building Docker images...$(NC)"
	docker compose build --no-cache
	@echo "$(GREEN)[+] Build complete$(NC)"

logs:
	docker compose logs -f --tail=50

logs-detection:
	docker compose logs -f detection-engine

logs-collector:
	docker compose logs -f log-collector

logs-correlation:
	docker compose logs -f correlation-engine

status:
	@echo ""
	@echo "$(GREEN)Container status:$(NC)"
	@docker compose ps
	@echo ""
	@echo "$(GREEN)Elasticsearch:$(NC)"
	@curl -s http://localhost:9200/_cluster/health | \
		python3 -c "import sys,json; d=json.load(sys.stdin); \
		print(f'  Status: {d[\"status\"]} | Indices: {d[\"number_of_data_nodes\"]} node(s)')" \
		2>/dev/null || echo "  Not reachable"
	@echo ""

test:
	@echo "$(GREEN)[*] Running tests (in venv)...$(NC)"
	@source venv/bin/activate && python3 tests/test_rules.py
	@echo "$(GREEN)[*] Validating SIGMA rules...$(NC)"
	@source venv/bin/activate && python3 sigma/sigma_converter.py
	@echo "$(GREEN)[*] Checking ES connection...$(NC)"
	@curl -sf http://localhost:9200 > /dev/null && \
		echo "  $(GREEN)Elasticsearch: OK$(NC)" || \
		echo "  $(RED)Elasticsearch: UNREACHABLE$(NC)"
	@echo "$(GREEN)[+] Tests complete$(NC)"

sigma:
	@echo "$(GREEN)[*] Converting SIGMA rules (in venv)...$(NC)"
	@source venv/bin/activate && python3 sigma/sigma_converter.py
	@echo "$(GREEN)[+] Output in sigma/output/$(NC)"

clean:
	@echo "$(RED)[!] This will remove all containers and volumes$(NC)"
	@read -p "Are you sure? [y/N] " confirm; \
		[ "$$confirm" = "y" ] && docker compose down -v || echo "Cancelled"

kibana:
	open http://localhost:5601