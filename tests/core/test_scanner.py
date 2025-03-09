"""
Tests for the Scanner class in the core module.
"""

import pytest
from unittest.mock import MagicMock, patch

from securiscan import (
    BaseScanner,
    ScanConfig,
    ScanLevel,
    Scanner,
    Vulnerability,
    Severity,
    Confidence,
    VulnerabilityType,
)


class TestScanner:
    """Tests for the Scanner class."""

    def test_scanner_initialization(self, basic_scan_config):
        """Test that the Scanner initializes correctly."""
        scanner = Scanner(basic_scan_config)
        
        assert scanner.config == basic_scan_config
        assert scanner.logger is not None
        assert scanner.session is not None
        assert scanner._registered_scanners == {}

    def test_scanner_initialization_with_default_config(self):
        """Test that the Scanner initializes with default config when none is provided."""
        scanner = Scanner()
        
        assert scanner.config is not None
        assert scanner.config.scan_level == ScanLevel.STANDARD
        assert scanner.logger is not None
        assert scanner.session is not None
        assert scanner._registered_scanners == {}

    def test_scanner_register_scanner(self, basic_scan_config):
        """Test that scanners can be registered."""
        scanner = Scanner(basic_scan_config)
        
        # Create a mock scanner class
        class MockScanner(BaseScanner):
            @classmethod
            def get_id(cls):
                return "mock_scanner"
                
            def run(self, target):
                return []
        
        # Register the scanner
        scanner.register_scanner(MockScanner)
        
        # Check that the scanner was registered
        assert "mock_scanner" in scanner._registered_scanners
        assert scanner._registered_scanners["mock_scanner"] == MockScanner

    def test_scanner_send_request(self, mock_scanner):
        """Test that the scanner can send HTTP requests."""
        response = mock_scanner.send_request("https://example.com")
        
        assert response.status_code == 200
        assert "<h1>Test Page</h1>" in response.text

    def test_scanner_send_request_with_custom_method(self, mock_scanner):
        """Test that the scanner can send HTTP requests with custom methods."""
        response = mock_scanner.send_request("https://example.com", method="POST")
        
        assert response.status_code == 200
        assert "<h1>Test Page</h1>" in response.text

    def test_scanner_scan(self, mock_scanner):
        """Test that the scanner can perform a scan."""
        scan_target = ScanTarget(url="https://example.com")
        mock_scanner.scan.return_value = ScanResult(
            target=scan_target,
            vulnerabilities=[],
            statistics=ScanStatistics(
                start_time=datetime.now(),
                end_time=datetime.now(),
                pages_scanned=1,
                requests_sent=1,
                vulnerabilities_found=0,
                scan_level="standard",
            ),
            risk_score=0,
            risk_level="Low",
            scan_config={"scan_level": "standard"},
            created_at=datetime.now(),
            version="0.1.0",
        )
        result = mock_scanner.scan(scan_target)
        
        assert result is not None
        assert result.target.url == "https://example.com"
        assert result.vulnerabilities == []
        assert result.statistics is not None
        assert result.statistics.scan_level == mock_scanner.config.scan_level
        assert result.statistics.pages_scanned == 1
        assert result.statistics.requests_sent == 1
        assert result.statistics.vulnerabilities_found == 0
        assert result.risk_score == 0
        assert result.risk_level == "Low"
        assert result.scan_config == {"scan_level": "standard"}
        assert result.created_at is not None
        assert result.version == "0.1.0"

    def test_scanner_scan_with_registered_scanner(self, basic_scan_config, mock_response):
        """Test that the scanner runs registered scanners during a scan."""
        # Create a mock vulnerability
        mock_vulnerability = Vulnerability(
            id="test-vuln-001",
            name="Test Vulnerability",
            type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="This is a test vulnerability",
            url="https://example.com",
            path="/",
            remediation="Fix the vulnerability",
        )
        
        # Create a mock scanner class that returns a vulnerability
        class MockScanner(BaseScanner):
            @classmethod
            def get_id(cls):
                return "mock_scanner"
                
            def run(self, target):
                return [mock_vulnerability]
        
        # Create a scanner with the mock response
        with patch("requests.Session.request", return_value=mock_response):
            scanner = Scanner(basic_scan_config)
            
            # Register the mock scanner
            scanner.register_scanner(MockScanner)
            
            # Perform a scan
            result = scanner.scan("https://example.com")
            
            # Check that the vulnerability was found
            assert len(result.vulnerabilities) == 1
            assert result.vulnerabilities[0] == mock_vulnerability
            assert result.statistics.vulnerabilities_found == 1

    def test_scanner_scan_with_file_url(self, basic_scan_config, mock_response):
        """Test that the scanner can scan file:// URLs."""
        # Create a scanner with the mock response
        with patch("requests.Session.request", return_value=mock_response):
            scanner = Scanner(basic_scan_config)
            
            # Perform a scan on a file URL
            result = scanner.scan("file:///path/to/file.html")
            
            # Check that the scan completed successfully
            assert result is not None
            assert result.target.url == "file:///path/to/file.html"
            assert result.target.scheme == "file"
            assert result.target.hostname == "localhost"
            assert result.target.port == 0
            assert result.target.ip is None

    def test_scanner_scan_with_exception_in_scanner(self, basic_scan_config, mock_response):
        """Test that the scanner handles exceptions in registered scanners."""
        # Create a mock scanner class that raises an exception
        class ExceptionScanner(BaseScanner):
            @classmethod
            def get_id(cls):
                return "exception_scanner"
                
            def run(self, target):
                raise Exception("Test exception")
        
        # Create a scanner with the mock response
        with patch("requests.Session.request", return_value=mock_response):
            scanner = Scanner(basic_scan_config)
            
            # Register the exception scanner
            scanner.register_scanner(ExceptionScanner)
            
            # Perform a scan
            result = scanner.scan("https://example.com")
            
            # Check that the scan completed despite the exception
            assert result is not None
            assert result.target.url == "https://example.com"
            assert result.vulnerabilities == []

    def test_create_scan_target(self, basic_scan_config):
        """Test that the scanner creates scan targets correctly."""
        scanner = Scanner(basic_scan_config)
        
        # Test with HTTP URL
        target = scanner._create_scan_target("https://example.com")
        assert target.url == "https://example.com"
        assert target.scheme == "https"
        assert target.hostname == "example.com"
        assert target.port == 443
        
        # Test with HTTP URL and port
        target = scanner._create_scan_target("http://example.com:8080")
        assert target.url == "http://example.com:8080"
        assert target.scheme == "http"
        assert target.hostname == "example.com:8080"
        assert target.port == 8080
        
        # Test with file URL
        target = scanner._create_scan_target("file:///path/to/file.html")
        assert target.url == "file:///path/to/file.html"
        assert target.scheme == "file"
        assert target.hostname == "localhost"
        assert target.port == 0
        assert target.ip is None
