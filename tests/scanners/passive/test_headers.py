"""
Tests for the HTTP Headers Scanner Module.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from securiscan.scanners.passive.headers import SecurityHeadersScanner, CacheControlScanner
from securiscan.core.result import (
    ScanTarget,
    Vulnerability,
    VulnerabilityType,
    Severity,
    Confidence,
)


class TestSecurityHeadersScanner:
    """Tests for the SecurityHeadersScanner class."""

    def test_run_with_no_issues(self, mock_scanner):
        """Test that run returns no vulnerabilities when all security headers are present."""
        # Create a mock response with all security headers
        mock_response = MagicMock()
        mock_response.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer-when-downgrade",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cache-Control": "no-store, max-age=0",
        }
        mock_response.cookies = []
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that no vulnerabilities were found
        assert len(vulnerabilities) == 0

    def test_run_with_missing_headers(self, mock_scanner):
        """Test that run returns vulnerabilities when security headers are missing."""
        # Create a mock response with missing security headers
        mock_response = MagicMock()
        mock_response.headers = {
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
        }
        mock_response.cookies = []
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for missing security headers
        missing_headers_vuln = next(
            (v for v in vulnerabilities if v.name == "Missing Security Headers"),
            None,
        )
        assert missing_headers_vuln is not None
        assert missing_headers_vuln.type == VulnerabilityType.INSECURE_HEADERS
        assert missing_headers_vuln.severity == Severity.MEDIUM  # Medium because critical headers are missing
        assert missing_headers_vuln.confidence == Confidence.HIGH
        
        # Check that the evidence contains the missing headers
        assert len(missing_headers_vuln.evidence) == 1
        evidence = missing_headers_vuln.evidence[0]
        assert evidence.type == "response_headers"
        assert "Strict-Transport-Security" in evidence.data
        assert "Content-Security-Policy" in evidence.data
        assert "X-Frame-Options" in evidence.data

    def test_run_with_information_disclosure(self, mock_scanner):
        """Test that run returns vulnerabilities when headers disclose information."""
        # Create a mock response with headers that disclose information
        mock_response = MagicMock()
        mock_response.headers = {
            "Server": "Apache/2.4.29 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
        }
        mock_response.cookies = []
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for information disclosure
        info_disclosure_vuln = next(
            (v for v in vulnerabilities if v.name == "Information Disclosure in HTTP Headers"),
            None,
        )
        assert info_disclosure_vuln is not None
        assert info_disclosure_vuln.type == VulnerabilityType.INFORMATION_DISCLOSURE
        assert info_disclosure_vuln.severity == Severity.LOW
        assert info_disclosure_vuln.confidence == Confidence.HIGH
        
        # Check that the evidence contains the disclosed information
        assert len(info_disclosure_vuln.evidence) == 1
        evidence = info_disclosure_vuln.evidence[0]
        assert evidence.type == "response_headers"
        assert "Server" in evidence.data
        assert evidence.data["Server"] == "Apache/2.4.29 (Ubuntu)"
        assert "X-Powered-By" in evidence.data
        assert evidence.data["X-Powered-By"] == "PHP/7.4.3"
        assert "X-AspNet-Version" in evidence.data
        assert evidence.data["X-AspNet-Version"] == "4.0.30319"

    def test_run_with_insecure_cookies(self, mock_scanner):
        """Test that run returns vulnerabilities when cookies are insecure."""
        # Create a mock response with insecure cookies
        mock_response = MagicMock()
        mock_response.headers = {
            "Set-Cookie": "session=abc123; Path=/",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
        }
        
        # Create mock cookies
        mock_cookie = MagicMock()
        mock_cookie.name = "session"
        mock_cookie.secure = False
        mock_cookie.has_nonstandard_attr.return_value = False
        mock_cookie.get_nonstandard_attr.return_value = None
        
        mock_response.cookies = [mock_cookie]
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for insecure cookies
        insecure_cookies_vuln = next(
            (v for v in vulnerabilities if v.name == "Insecure Cookies"),
            None,
        )
        assert insecure_cookies_vuln is not None
        assert insecure_cookies_vuln.type == VulnerabilityType.INSECURE_COOKIE
        assert insecure_cookies_vuln.severity == Severity.MEDIUM  # Medium because Secure flag is missing on HTTPS
        assert insecure_cookies_vuln.confidence == Confidence.HIGH
        
        # Check that the evidence contains the insecure cookies
        assert len(insecure_cookies_vuln.evidence) == 1
        evidence = insecure_cookies_vuln.evidence[0]
        assert evidence.type == "cookies"
        assert len(evidence.data) == 1
        assert evidence.data[0]["name"] == "session"
        assert "Missing Secure flag" in evidence.data[0]["issues"]
        assert "Missing HttpOnly flag" in evidence.data[0]["issues"]
        assert "Missing SameSite attribute" in evidence.data[0]["issues"]

    def test_run_with_cors_misconfiguration(self, mock_scanner):
        """Test that run returns vulnerabilities when CORS is misconfigured."""
        # Create a mock response with CORS misconfiguration
        mock_response = MagicMock()
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
        }
        mock_response.cookies = []
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for CORS misconfiguration
        cors_vuln = next(
            (v for v in vulnerabilities if v.name == "CORS Misconfiguration"),
            None,
        )
        assert cors_vuln is not None
        assert cors_vuln.type == VulnerabilityType.CORS_MISCONFIGURATION
        assert cors_vuln.severity == Severity.MEDIUM
        assert cors_vuln.confidence == Confidence.HIGH
        
        # Check that the evidence contains the CORS issues
        assert len(cors_vuln.evidence) == 1
        evidence = cors_vuln.evidence[0]
        assert evidence.type == "cors_headers"
        assert "Access-Control-Allow-Origin set to wildcard (*)" in evidence.data
        assert "Access-Control-Allow-Credentials is true with wildcard Access-Control-Allow-Origin" in evidence.data

    def test_run_with_missing_clickjacking_protection(self, mock_scanner):
        """Test that run returns vulnerabilities when clickjacking protection is missing."""
        # Create a mock response without clickjacking protection
        mock_response = MagicMock()
        mock_response.headers = {
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
        }
        mock_response.cookies = []
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for missing clickjacking protection
        clickjacking_vuln = next(
            (v for v in vulnerabilities if v.name == "Missing Clickjacking Protection"),
            None,
        )
        assert clickjacking_vuln is not None
        assert clickjacking_vuln.type == VulnerabilityType.CLICKJACKING
        assert clickjacking_vuln.severity == Severity.MEDIUM
        assert clickjacking_vuln.confidence == Confidence.HIGH
        
        # Check that the evidence contains the missing header
        assert len(clickjacking_vuln.evidence) == 1
        evidence = clickjacking_vuln.evidence[0]
        assert evidence.type == "missing_header"
        assert evidence.data["header"] == "X-Frame-Options or CSP frame-ancestors"

    def test_run_with_exception(self, mock_scanner):
        """Test that run handles exceptions gracefully."""
        # Mock the scanner's send_request method to raise an exception
        mock_scanner.send_request.side_effect = Exception("Test exception")
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = SecurityHeadersScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that no vulnerabilities were found
        assert len(vulnerabilities) == 0


class TestCacheControlScanner:
    """Tests for the CacheControlScanner class."""

    def test_run_with_no_issues(self, mock_scanner):
        """Test that run returns no vulnerabilities when cache control is properly configured."""
        # Create a mock response with proper cache control
        mock_response = MagicMock()
        mock_response.headers = {
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        }
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = CacheControlScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that no vulnerabilities were found
        assert len(vulnerabilities) == 0

    def test_run_with_missing_cache_control(self, mock_scanner):
        """Test that run returns vulnerabilities when cache control is missing."""
        # Create a mock response without cache control
        mock_response = MagicMock()
        mock_response.headers = {}
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = CacheControlScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for insufficient cache control
        cache_vuln = next(
            (v for v in vulnerabilities if v.name == "Insufficient Cache Control"),
            None,
        )
        assert cache_vuln is not None
        assert cache_vuln.type == VulnerabilityType.SECURITY_MISCONFIGURATION
        assert cache_vuln.severity == Severity.LOW
        assert cache_vuln.confidence == Confidence.MEDIUM
        
        # Check that the evidence contains the cache issues
        assert len(cache_vuln.evidence) == 1
        evidence = cache_vuln.evidence[0]
        assert evidence.type == "cache_headers"
        assert "Missing Cache-Control header" in evidence.data
        assert "Missing 'Pragma: no-cache' header" in evidence.data
        assert "Missing Expires header" in evidence.data

    def test_run_with_weak_cache_control(self, mock_scanner):
        """Test that run returns vulnerabilities when cache control is weak."""
        # Create a mock response with weak cache control
        mock_response = MagicMock()
        mock_response.headers = {
            "Cache-Control": "public, max-age=86401",
            "Expires": "Wed, 21 Oct 2025 07:28:00 GMT",
        }
        
        # Mock the scanner's send_request method
        mock_scanner.send_request.return_value = mock_response
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = CacheControlScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that vulnerabilities were found
        assert len(vulnerabilities) > 0
        
        # Check that there's a vulnerability for insufficient cache control
        cache_vuln = next(
            (v for v in vulnerabilities if v.name == "Insufficient Cache Control"),
            None,
        )
        assert cache_vuln is not None
        assert cache_vuln.type == VulnerabilityType.SECURITY_MISCONFIGURATION
        assert cache_vuln.severity == Severity.LOW
        assert cache_vuln.confidence == Confidence.MEDIUM
        
        # Check that the evidence contains the cache issues
        assert len(cache_vuln.evidence) == 1
        evidence = cache_vuln.evidence[0]
        assert evidence.type == "cache_headers"
        assert "Cache-Control does not include 'private' or 'no-store'" in evidence.data
        assert "Long max-age value: 86401 seconds" in evidence.data
        assert "Missing 'Pragma: no-cache' header" in evidence.data

    def test_run_with_exception(self, mock_scanner):
        """Test that run handles exceptions gracefully."""
        # Mock the scanner's send_request method to raise an exception
        mock_scanner.send_request.side_effect = Exception("Test exception")
        
        # Create a target
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        # Create the scanner
        scanner = CacheControlScanner(mock_scanner)
        
        # Run the scanner
        vulnerabilities = scanner.run(target)
        
        # Check that no vulnerabilities were found
        assert len(vulnerabilities) == 0
