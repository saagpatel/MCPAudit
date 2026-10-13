.PHONY: install check test lint format typecheck clean audit help

# Default target
help:
	@echo "MCPAudit — available targets:"
	@echo ""
	@echo "  install    Install all dependencies (including dev)"
	@echo "  test       Run the full test suite"
	@echo "  check      Run the full non-mutating local quality gate"
	@echo "  lint       Run ruff lint + format check + mypy"
	@echo "  format     Auto-format source files with ruff"
	@echo "  typecheck  Run mypy type checking (strict)"
	@echo "  clean      Remove build artifacts and __pycache__ directories"
	@echo "  audit      Run mcp-audit against your local MCP config"
	@echo ""

install:
	uv sync --locked --dev

check:
	@command -v uv >/dev/null 2>&1 || { echo "uv is required; install it from https://docs.astral.sh/uv/" >&2; exit 127; }
	uv run ruff check .
	uv run ruff format --check
	uv run mypy .
	uv run pytest -q

test:
	uv run pytest tests/ -v

lint:
	uv run ruff check .
	uv run ruff format --check
	uv run mypy .

format:
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

typecheck:
	uv run mypy .

clean:
	rm -rf dist/ build/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

audit:
	uv run mcp-audit check
