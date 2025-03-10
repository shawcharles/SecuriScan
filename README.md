# SecuriScan (work in progress)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11-blue)](https://www.python.org/)
[![Documentation Status](https://readthedocs.org/projects/securiscan/badge/?version=latest)](https://securiscan.readthedocs.io/en/latest/?badge=latest)
[![Author](https://img.shields.io/badge/Author-Charles%20Shaw-brightgreen)](https://github.com/shawcharles)

**SecuriScan** is a web security testing framework designed to identify vulnerabilities in web applications. It provides a set of tools for security professionals, penetration testers, and developers to assess the security posture of web applications.

## Features

- **Security Scanning**: Detect common web vulnerabilities including OWASP Top 10
- **Passive Scanning**: Analyze websites without sending potentially harmful requests
- **Active Scanning**: Perform thorough security testing with configurable intensity levels
- **Continuous Monitoring**: Monitor websites for security issues over time
- **Detailed Reporting**: Generate reports in multiple formats (HTML, JSON, CSV, PDF)
- **Extensible Architecture**: Easily add custom scanners and modules
- **Command-line Interface**: Powerful CLI for automation and integration
- **Programmatic API**: Use as a library in your Python applications

## Installation

SecuriScan is not currently available on PyPI and must be installed from source.

### From Source

```bash
git clone https://github.com/shawcharles/SecuriScan.git
cd SecuriScan
pip install -e .
```

### With Optional Dependencies

After installing from source, you can add optional dependencies:

```bash
# For browser automation
pip install -e ".[browser]"

# For PDF report generation
pip install -e ".[pdf]"

# For development
pip install -e ".[dev]"

# For documentation
pip install -e ".[docs]"

# All optional dependencies
pip install -e ".[all]"
```

## Quick Start

### Command-line Usage

```bash
# Basic scan
securiscan scan https://example.com

# Scan with specific level
securiscan scan --level aggressive https://example.com

# Save report
securiscan scan --output report.html https://example.com

# Continuous monitoring
securiscan monitor --interval 24 https://example.com

# List available scanner modules
securiscan list-modules
```

### Python API Usage

```python
from securiscan import Scanner, ScanConfig, ScanLevel

# Create scanner with custom configuration
config = ScanConfig(
    scan_level=ScanLevel.STANDARD,
    max_depth=3,
    threads=10,
    timeout=30,
)

# Create scanner
scanner = Scanner(config)

# Run scan
result = scanner.scan("https://example.com")

# Print vulnerabilities
for vuln in result.vulnerabilities:
    print(f"[{vuln.severity}] {vuln.name}: {vuln.description}")

# Generate report
result.generate_report("report.html", "html")
```

## Examples

Check out the [examples](examples/) directory for more usage examples:

- [Basic Scan](examples/basic_scan.py): Simple example of using the Scanner API
- [Continuous Monitoring](examples/continuous_monitoring.py): Example of continuous monitoring
- [Custom Scanner](examples/custom_scanner.py): Example of creating a custom scanner

## Documentation

For detailed documentation, visit [securiscan.readthedocs.io](https://securiscan.readthedocs.io/).

## Project History

The original code that served as the foundation for this project is preserved in the [legacy](legacy/) directory. These files are kept for historical reference and are no longer actively used in the project.

## Author

- [Charles Shaw](https://github.com/shawcharles) - charles@charlesshaw.net

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for security professionals, penetration testers, and developers to test their own systems and applications. Do not use this tool to scan websites or systems without explicit permission. The authors are not responsible for any misuse or damage caused by this tool.
