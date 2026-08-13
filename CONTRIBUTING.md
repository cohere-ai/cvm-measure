# Contributing to cvm-measure

Thank you for your interest in contributing! This document explains how
to get started.

## Development setup

```bash
git clone https://github.com/cohere-ai/cvm-measure.git
cd cvm-measure
pip install -e ".[dev]"
pre-commit install
```

## Running tests

```bash
python -m pytest tests/ -v
```

Some tests require binary fixtures (OVMF firmware, UKI, CCEL) that are
not checked into the repository due to size. Tests that need missing
fixtures are automatically skipped. See the READMEs in
`tests/fixtures/` for how to obtain them.

## Code style

This project uses:

- **[Ruff](https://docs.astral.sh/ruff/)** for linting and formatting
- **[mypy](https://mypy.readthedocs.io/)** in strict mode for type checking
- **[Bandit](https://bandit.readthedocs.io/)** for security linting

All checks run automatically via pre-commit hooks on every commit.

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/).
The pre-commit hook enforces this via
[commitizen](https://commitizen-tools.github.io/commitizen/). Examples:

- `feat: add AMD SEV-SNP support`
- `fix: handle firmware files with no TDX metadata`
- `refactor: simplify CCEL parser`
- `docs: update baseline instructions`

## Submitting a pull request

1. Fork the repository and create a branch from `main`.
2. Make your changes and add tests for new functionality.
3. Ensure all tests pass and pre-commit hooks are clean.
4. Open a pull request with a clear description of the change.

## Reporting issues

Open a [GitHub issue](https://github.com/cohere-ai/cvm-measure/issues)
with steps to reproduce, expected behavior, and actual behavior.

## License

By contributing, you agree that your contributions will be licensed
under the Apache License 2.0.
