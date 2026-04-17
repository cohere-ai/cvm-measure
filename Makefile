.PHONY: install test lint typecheck clean

install:
	pip install -e ".[dev]"

test:
	python3 -m pytest tests/ -v

lint:
	python3 -m ruff check src/ tests/

typecheck:
	python3 -m mypy src/

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
