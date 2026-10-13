.PHONY: install dev test lint demo serve evaluate docker clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check src tests

demo:
	socprio demo

serve:
	socprio serve

evaluate:
	socprio generate -n 5000 --hours 96 -o var/benchmark.jsonl
	socprio evaluate --data var/benchmark.jsonl

docker:
	docker compose up --build

clean:
	rm -rf var reports models/*.joblib .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
