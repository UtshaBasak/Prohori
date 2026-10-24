# Convenience targets only; every target is a plain `uv` command you can run directly.
.PHONY: install lint format typecheck test cov check build clean

install:
	uv sync
	uv run pre-commit install

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy

test:
	uv run pytest

cov:
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck cov

build:
	uv build

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
