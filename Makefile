.PHONY: up down restart build logs test test-e2e clean psql shell

# Build and start the entire stack
up:
	docker compose up -d --build

# Stop the stack and remove containers
down:
	docker compose down

# Stop the stack, remove containers and volumes (Warning: destructive)
clean:
	docker compose down -v

# Restart backend service
restart-backend:
	docker compose restart backend

# View logs for the entire stack or a specific service (e.g. make logs service=backend)
logs:
	docker compose logs -f $(service)

# Run backend unit/integration tests
test:
	docker compose exec -e PYTHONPATH=/app backend pytest tests/test_api.py -v

# Run full end-to-end pipeline test
test-e2e:
	docker compose exec -e PYTHONPATH=/app backend python tests/test_pipeline.py

# Open a psql shell to the database
psql:
	docker compose exec postgres psql -U siemuser -d siemdb

# Open a bash shell in the backend container
shell:
	docker compose exec backend /bin/bash
