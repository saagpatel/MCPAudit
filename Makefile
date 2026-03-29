.PHONY: install test lint format typecheck clean audit help

# Default target
help:
	@echo "MCPAudit — available targets:"
	@echo ""
	@echo "  install    Install all dependencies (including dev)"
	@echo "  test       Run the full test suite"
	@echo "  lint       Run ruff lint + format check + mypy"
	@echo "  format     Auto-format source files with ruff"
	@echo "  typecheck  Run mypy type checking (strict)"
	@echo "  clean      Remove build artifacts and __pycache__ directories"
	@echo "  audit      Run mcp-audit against your local MCP config"
	@echo ""

install:
	uv sync --dev

test:
	uv run pytest tests/ -v

lint:
	uv run ruff check src/ tests/
	uv run ruff format --check src/ tests/
	uv run mypy src/ --strict

format:
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

typecheck:
	uv run mypy src/ --strict

clean:
	rm -rf dist/ build/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

audit:
	uv run mcp-audit
