# Contributing to reconflow

Thank you for your interest in contributing to `reconflow`.

## Pull Request Policy

All contributions—including bug fixes, documentation improvements, and new stage plugins—**are accepted exclusively via GitHub Pull Requests**. Please do not submit code changes via email, issue attachments, or external patches.

---

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/reconflow.git
   cd reconflow
   ```

2. Create a virtual environment and install development dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install flake8
   pip install -e .
   ```

3. Run the automated test suite:
   ```bash
   python -m unittest discover tests -v
   ```

---

## Contribution Guidelines

1. **Safety & Scope Boundaries**:
   - `reconflow` enforces strict fail-closed scope checking. Any changes to pipeline orchestration, target parsing, or external tool execution must preserve scope boundary validation.
   - External tools must never receive targets outside the user's scope configuration.

2. **Code Style & Linting**:
   - Adhere to PEP 8 standards. Verify compliance with:
     ```bash
     flake8 reconflow tests --max-line-length=100 --ignore=E203,W503,W504
     ```

3. **Testing**:
   - Every bug fix or new capability must include corresponding unit or integration tests in `tests/`.
   - Never mock numbers or bypass test assertions.
   - All 176+ tests must pass before submitting a pull request.

4. **Pull Request Process**:
   - Branch from `main` (e.g., `git checkout -b fix-scope-cidr-matching`).
   - Write clear, focused commit messages following the Conventional Commits specification (e.g., `fix(scope):`, `feat(plugin):`, `test(diff):`).
   - Open a pull request against `main`. Ensure all GitHub Actions CI checks are passing.
