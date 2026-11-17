.PHONY: test lint install dev clean scan help

help:
	@echo "Venom — development targets"
	@echo ""
	@echo "  make install    Install venom in editable mode"
	@echo "  make dev        Install with dev dependencies"
	@echo "  make test       Run test suite"
	@echo "  make scan       Run venom on samples/"
	@echo "  make clean      Remove build artifacts"
	@echo "  make check      Verify analyzer availability"

install:
	pip install -e .

dev:
	pip install -e ".[all,dev]"

test:
	python3 -m pytest tests/ -v --tb=short

scan:
	python3 -m venom samples/ --no-llm --html -o output -v

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

check:
	@python3 -c "\
	from venom.analyzers import get_all_analyzers; \
	analyzers = get_all_analyzers(); \
	ready = [a for a in analyzers if a.is_available()]; \
	missing = [a for a in analyzers if not a.is_available()]; \
	print(f'Analyzers: {len(ready)}/{len(analyzers)} available'); \
	print(); \
	[print(f'  [OK] {a.name}') for a in ready]; \
	[print(f'  [--] {a.name}') for a in missing]; \
	"
