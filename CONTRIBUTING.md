<![CDATA[# Contributing to security-module

Thank you for your interest in contributing to **security-module**! This project
is an agent-agnostic safety and red-team evaluation harness for agentic AI systems.

## Getting Started

1. **Fork & clone** the repository
2. **Install dependencies**:
   ```bash
   pip install -e ".[llm,dev]"
   ```
3. **Run the test suite** to make sure everything is green:
   ```bash
   python -m pytest tests/ -q --ignore=tests/test_scan_v3_live.py
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes, ensuring all tests pass
3. Submit a pull request with a clear description

## Code Standards

- **Python 3.11+** — use type hints where practical
- **Pydantic v2** for data models
- Follow existing code style and conventions
- Add tests for new features in `tests/`

## Adding a New Threat Suite

1. Create a new file in `tests_asi/` following the naming convention:
   - ASI suites: `asi{NN}_{name}.py`
   - Extended suites: `ext{NN}_{name}.py`
2. Use the `@register_tester` decorator from `core/tester_registry.py`
3. Extend `BaseTester` from `core/base_tester.py`
4. Add corresponding payloads in `payloads/` if needed

## Reporting Security Issues

If you discover a security vulnerability in this tool, please report it
responsibly. See [SECURITY.md](SECURITY.md) for details.

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
]]>
