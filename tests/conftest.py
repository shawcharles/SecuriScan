"""
Pytest configuration and fixtures for SecuriScan tests.
"""

import os
import pytest
import requests
from unittest.mock import MagicMock, patch

from securiscan import (
    AuthConfig,
    AuthType,
    ProxyConfig,
    ScanConfig,
    ScanLevel,
    Scanner,
    Vulnerability,
    Severity,
    Confidence,
    VulnerabilityType,
    Evidence,
)


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    mock = MagicMock(spec=requests.Response)
    mock.status_code = 200
    mock.text = "<html><body><h1>Test Page</h1></body></html>"
    mock.headers = {
        "Content-Type": "text/html",
        "Server": "nginx/1.19.0",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }
    return mock


@pytest.fixture
def mock_vulnerable_response():
    """Create a mock HTTP response with vulnerabilities."""
    mock = MagicMock(spec=requests.Response)
    mock.status_code = 200
    mock.text = """
    <html>
    <body>
        <h1>Test Vulnerable Page</h1>
        <p>Contact us at test@example.com or admin@example.com</p>
        <form action="search.php" method="GET">
            <input type="text" name="q">
            <input type="submit" value="Search">
        </form>
        <script>
            var user = getParameterByName('user');
            document.write('<h2>Welcome, ' + user + '</h2>');
        </script>
    </body>
    </html>
    """
    mock.headers = {
        "Content-Type": "text/html",
        "Server": "Apache/2.4.29",
        # Missing security headers
    }
    return mock


@pytest.fixture
def basic_scan_config():
    """Create a basic scan configuration."""
    return ScanConfig(
        scan_level=ScanLevel.PASSIVE,
        max_depth=1,
        threads=1,
        timeout=5,
    )


@pytest.fixture
def standard_scan_config():
    """Create a standard scan configuration."""
    return ScanConfig(
        scan_level=ScanLevel.STANDARD,
        max_depth=2,
        threads=2,
        timeout=10,
    )


@pytest.fixture
def aggressive_scan_config():
    """Create an aggressive scan configuration."""
    return ScanConfig(
        scan_level=ScanLevel.AGGRESSIVE,
        max_depth=3,
        threads=5,
        timeout=30,
    )


@pytest.fixture
def auth_config():
    """Create an authentication configuration."""
    return AuthConfig(
        username="testuser",
        password="testpass",
        auth_type=AuthType.BASIC,
    )


@pytest.fixture
def proxy_config():
    """Create a proxy configuration."""
    return ProxyConfig(
        url="http://localhost:8080",
    )


@pytest.fixture
def mock_scanner(basic_scan_config, mock_response):
    """Create a scanner with mocked HTTP requests."""
    with patch("requests.Session.request", return_value=mock_response):
        scanner = Scanner(basic_scan_config)
        yield scanner


@pytest.fixture
def mock_vulnerable_scanner(basic_scan_config, mock_vulnerable_response):
    """Create a scanner with mocked HTTP requests returning vulnerable content."""
    with patch("requests.Session.request", return_value=mock_vulnerable_response):
        scanner = Scanner(basic_scan_config)
        yield scanner


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    evidence = Evidence(
        type="test_evidence",
        data={"test_key": "test_value"},
        description="Test evidence description",
    )
    
    return Vulnerability(
        id="test-vuln-001",
        name="Test Vulnerability",
        type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="This is a test vulnerability",
        url="https://example.com/vulnerable-page",
        path="/vulnerable-page",
        parameter="q",
        evidence=[evidence],
        remediation="Fix the vulnerability by implementing proper input validation",
        references=["https://owasp.org/www-project-top-ten/"],
        cwe=79,  # CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
        tags={"xss", "injection", "test"},
    )


@pytest.fixture
def temp_report_dir(tmpdir):
    """Create a temporary directory for report files."""
    report_dir = tmpdir.mkdir("reports")
    return str(report_dir)
