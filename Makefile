.PHONY: install check test lint format typecheck clean audit help base twins

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
	@echo "  base       Verify inert mcpforge fixture (REGEN=1 to replace)"
	@echo "  twins      Generate and verify the inert mutation range"
	@echo ""

install:
	uv sync --all-packages --locked --dev

base:
	uv run --locked python -m redteam.range.base.build $(if $(filter 1,$(REGEN)),--regen,)

twins:
	uv run --locked python -m redteam.range.gen

check:
	@command -v uv >/dev/null 2>&1 || { echo "uv is required; install it from https://docs.astral.sh/uv/" >&2; exit 127; }
	uv run --locked ruff check .
	uv run --locked ruff format --check
	uv run --locked mypy .
	uv run --locked pytest -q

test:
	uv run --locked pytest tests/ -v

lint:
	uv run --locked ruff check .
	uv run --locked ruff format --check
	uv run --locked mypy .

format:
	uv run --locked ruff check --fix src/ tests/
	uv run --locked ruff format src/ tests/

typecheck:
	uv run --locked mypy .

clean:
	rm -rf dist/ build/ .mypy_cache/ .ruff_cache/ .pytest_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

audit:
	uv run --locked mcp-audit check
