# Contributing to SecuriScan

Thank you for your interest in contributing to SecuriScan! This document provides guidelines and instructions for contributing to this project maintained by [Charles Shaw](https://github.com/shawcharles).

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for SecuriScan. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

- **Use the GitHub issue tracker** - Use the [GitHub issue tracker](https://github.com/shawcharles/SecuriScan/issues) to report bugs.
- **Check if the bug has already been reported** - Before creating a new issue, please search existing issues to see if the problem has already been reported.
- **Use the bug report template** - When creating a new issue, use the bug report template if available.
- **Provide detailed information** - Include as much information as possible, such as:
  - A clear and descriptive title
  - Steps to reproduce the issue
  - Expected behavior
  - Actual behavior
  - Screenshots or logs if applicable
  - Environment details (OS, Python version, etc.)

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for SecuriScan, including completely new features and minor improvements to existing functionality.

- **Use the GitHub issue tracker** - Use the [GitHub issue tracker](https://github.com/shawcharles/SecuriScan/issues) to suggest enhancements.
- **Check if the enhancement has already been suggested** - Before creating a new issue, please search existing issues to see if the enhancement has already been suggested.
- **Use the feature request template** - When creating a new issue, use the feature request template if available.
- **Provide detailed information** - Include as much information as possible, such as:
  - A clear and descriptive title
  - A detailed description of the proposed enhancement
  - Any potential implementation details
  - Why this enhancement would be useful to most SecuriScan users

### Pull Requests

This section guides you through submitting a pull request for SecuriScan.

- **Follow the coding style** - Make sure your code follows the coding style of the project.
- **Document your changes** - Add or update documentation as necessary.
- **Include tests** - Add tests for your changes if applicable.
- **Update the changelog** - Update the changelog if applicable.
- **Submit a pull request** - Submit a pull request from your fork to the main repository.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip
- git

### Setting Up the Development Environment

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/shawcharles/SecuriScan.git
   cd SecuriScan
   ```
3. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```
4. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```
5. Set up pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running Tests

```bash
pytest
```

### Running Linters

```bash
# Run black
black .

# Run isort
isort .

# Run flake8
flake8 .

# Run mypy
mypy .
```

## Style Guide

### Python Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide.
- Use [Black](https://black.readthedocs.io/) for code formatting.
- Use [isort](https://pycqa.github.io/isort/) for import sorting.
- Use [flake8](https://flake8.pycqa.org/) for linting.
- Use [mypy](https://mypy.readthedocs.io/) for type checking.

### Documentation Style

- Use [Google style docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings).
- Document all public modules, classes, methods, and functions.
- Keep docstrings up-to-date with code changes.

### Commit Message Style

- Use the present tense ("Add feature" not "Added feature").
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
- Limit the first line to 72 characters or less.
- Reference issues and pull requests liberally after the first line.

## License

By contributing to SecuriScan, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
