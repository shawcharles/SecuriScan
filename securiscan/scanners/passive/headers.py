"""
HTTP Headers Scanner Module.

This module analyzes HTTP headers for security issues.
"""

import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from pydantic import HttpUrl

from securiscan.core.result import Confidence, Evidence, Severity, ScanTarget, Vulnerability, VulnerabilityType
from securiscan.core.scanner import BaseScanner, Scanner


class SecurityHeadersScanner(BaseScanner):
    """Scanner for checking security headers."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the security headers scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Checking security headers for {target.url}")
        vulnerabilities = []

        try:
            # Send request to the target
            response = self.scanner.send_request(target.url)
            
            # Check for missing security headers
            missing_headers = self._check_missing_security_headers(response.headers)
            if missing_headers:
                vuln = self._create_missing_headers_vulnerability(target.url, missing_headers)
                vulnerabilities.append(vuln)
            
            # Check for information disclosure in headers
            disclosed_info = self._check_information_disclosure(response.headers)
            if disclosed_info:
                vuln = self._create_info_disclosure_vulnerability(target.url, disclosed_info)
                vulnerabilities.append(vuln)
            
            # Check for insecure cookies
            if 'Set-Cookie' in response.headers:
                insecure_cookies = self._check_insecure_cookies(response.cookies)
                if insecure_cookies:
                    vuln = self._create_insecure_cookies_vulnerability(target.url, insecure_cookies)
                    vulnerabilities.append(vuln)
            
            # Check for CORS misconfiguration
            cors_issues = self._check_cors_headers(response.headers)
            if cors_issues:
                vuln = self._create_cors_vulnerability(target.url, cors_issues)
                vulnerabilities.append(vuln)
            
            # Check for clickjacking protection
            if not self._has_clickjacking_protection(response.headers):
                vuln = self._create_clickjacking_vulnerability(target.url)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error checking security headers: {str(e)}", exc_info=True)
            return []

    def _check_missing_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Check for missing security headers.

        Args:
            headers: HTTP headers

        Returns:
            Dictionary of missing headers and their recommended values
        """
        # Define recommended security headers
        recommended_headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer-when-downgrade",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cache-Control": "no-store, max-age=0",
        }
        
        # Convert header keys to lowercase for case-insensitive comparison
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Find missing headers
        missing = {}
        for header, value in recommended_headers.items():
            if header.lower() not in headers_lower:
                missing[header] = value
        
        return missing

    def _check_information_disclosure(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Check for information disclosure in headers.

        Args:
            headers: HTTP headers

        Returns:
            Dictionary of headers that disclose sensitive information
        """
        sensitive_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "X-Generator",
            "X-Drupal-Cache",
            "X-Drupal-Dynamic-Cache",
            "X-Varnish",
            "Via",
            "X-Backend-Server",
        ]
        
        disclosed = {}
        for header in sensitive_headers:
            if header in headers:
                disclosed[header] = headers[header]
        
        return disclosed

    def _check_insecure_cookies(self, cookies: requests.cookies.RequestsCookieJar) -> List[Dict]:
        """Check for insecure cookies.

        Args:
            cookies: Cookies from the response

        Returns:
            List of insecure cookies with details
        """
        insecure_cookies = []
        
        for cookie in cookies:
            issues = []
            
            if not cookie.secure:
                issues.append("Missing Secure flag")
            
            if not cookie.has_nonstandard_attr("httponly"):
                issues.append("Missing HttpOnly flag")
            
            samesite = cookie.get_nonstandard_attr("samesite")
            if not samesite:
                issues.append("Missing SameSite attribute")
            elif samesite.lower() == "none" and not cookie.secure:
                issues.append("SameSite=None without Secure flag")
            
            if issues:
                insecure_cookies.append({
                    "name": cookie.name,
                    "issues": issues,
                    "secure": cookie.secure,
                    "httponly": cookie.has_nonstandard_attr("httponly"),
                    "samesite": cookie.get_nonstandard_attr("samesite"),
                })
        
        return insecure_cookies

    def _check_cors_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check for CORS misconfiguration.

        Args:
            headers: HTTP headers

        Returns:
            List of CORS issues
        """
        issues = []
        
        # Check Access-Control-Allow-Origin
        if "Access-Control-Allow-Origin" in headers:
            acao = headers["Access-Control-Allow-Origin"]
            if acao == "*":
                issues.append("Access-Control-Allow-Origin set to wildcard (*)")
            elif acao.startswith("http"):
                # Check for multiple origins (which is invalid)
                if "," in acao:
                    issues.append("Access-Control-Allow-Origin contains multiple origins")
        
        # Check Access-Control-Allow-Credentials
        if "Access-Control-Allow-Credentials" in headers:
            if headers["Access-Control-Allow-Credentials"].lower() == "true":
                if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
                    issues.append("Access-Control-Allow-Credentials is true with wildcard Access-Control-Allow-Origin")
        
        return issues

    def _has_clickjacking_protection(self, headers: Dict[str, str]) -> bool:
        """Check if the response has clickjacking protection.

        Args:
            headers: HTTP headers

        Returns:
            True if protected, False otherwise
        """
        # Check X-Frame-Options header
        if "X-Frame-Options" in headers:
            value = headers["X-Frame-Options"].upper()
            if value in ["DENY", "SAMEORIGIN"]:
                return True
        
        # Check Content-Security-Policy header for frame-ancestors directive
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "frame-ancestors" in csp and not "frame-ancestors 'none'" in csp:
                return True
        
        return False

    def _create_missing_headers_vulnerability(
        self, url: HttpUrl, missing_headers: Dict[str, str]
    ) -> Vulnerability:
        """Create a vulnerability for missing security headers.

        Args:
            url: Target URL
            missing_headers: Dictionary of missing headers

        Returns:
            Vulnerability object
        """
        # Determine severity based on which headers are missing
        severity = Severity.LOW
        critical_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
        for header in critical_headers:
            if header in missing_headers:
                severity = Severity.MEDIUM
                break
        
        # Create evidence
        evidence = Evidence(
            type="response_headers",
            data=missing_headers,
            description=f"Missing {len(missing_headers)} security headers",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Missing Security Headers",
            type=VulnerabilityType.INSECURE_HEADERS,
            severity=severity,
            confidence=Confidence.HIGH,
            description=f"The server is missing {len(missing_headers)} recommended security headers that help protect against common web vulnerabilities.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Add the missing security headers to the server configuration to improve security posture.",
            references=[
                "https://owasp.org/www-project-secure-headers/",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ],
            cwe=693,  # Protection Mechanism Failure
            tags={"security-headers", "hardening"},
        )

    def _create_info_disclosure_vulnerability(
        self, url: HttpUrl, disclosed_info: Dict[str, str]
    ) -> Vulnerability:
        """Create a vulnerability for information disclosure in headers.

        Args:
            url: Target URL
            disclosed_info: Dictionary of headers disclosing information

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="response_headers",
            data=disclosed_info,
            description=f"Headers disclosing sensitive information: {', '.join(disclosed_info.keys())}",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Information Disclosure in HTTP Headers",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="The server is disclosing potentially sensitive information through HTTP headers, which could help attackers identify the technology stack and target specific vulnerabilities.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Configure the server to remove or obfuscate headers that reveal server technologies and versions.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
            ],
            cwe=200,  # Information Exposure
            tags={"information-disclosure", "fingerprinting"},
        )

    def _create_insecure_cookies_vulnerability(
        self, url: HttpUrl, insecure_cookies: List[Dict]
    ) -> Vulnerability:
        """Create a vulnerability for insecure cookies.

        Args:
            url: Target URL
            insecure_cookies: List of insecure cookies with details

        Returns:
            Vulnerability object
        """
        # Determine severity based on the number and type of issues
        severity = Severity.LOW
        for cookie in insecure_cookies:
            if "Missing Secure flag" in cookie["issues"] and url.scheme == "https":
                severity = Severity.MEDIUM
                break
        
        # Create evidence
        evidence = Evidence(
            type="cookies",
            data=insecure_cookies,
            description=f"Found {len(insecure_cookies)} cookies with security issues",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Insecure Cookies",
            type=VulnerabilityType.INSECURE_COOKIE,
            severity=severity,
            confidence=Confidence.HIGH,
            description="The application sets cookies without proper security attributes, which could lead to cookie theft, session hijacking, or cross-site scripting attacks.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Set the Secure, HttpOnly, and SameSite attributes on all cookies containing sensitive information.",
            references=[
                "https://owasp.org/www-community/controls/SecureCookieAttribute",
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies",
            ],
            cwe=614,  # Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
            tags={"cookies", "session-management"},
        )

    def _create_cors_vulnerability(
        self, url: HttpUrl, cors_issues: List[str]
    ) -> Vulnerability:
        """Create a vulnerability for CORS misconfiguration.

        Args:
            url: Target URL
            cors_issues: List of CORS issues

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="cors_headers",
            data=cors_issues,
            description=f"CORS misconfiguration issues: {', '.join(cors_issues)}",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="CORS Misconfiguration",
            type=VulnerabilityType.CORS_MISCONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="The application has a Cross-Origin Resource Sharing (CORS) misconfiguration that could allow unauthorized websites to access sensitive data.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Configure CORS headers with specific origins instead of wildcards, especially when credentials are allowed.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                "https://portswigger.net/web-security/cors",
            ],
            cwe=942,  # Permissive Cross-domain Policy with Untrusted Domains
            tags={"cors", "api-security"},
        )

    def _create_clickjacking_vulnerability(self, url: HttpUrl) -> Vulnerability:
        """Create a vulnerability for clickjacking protection.

        Args:
            url: Target URL

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="missing_header",
            data={"header": "X-Frame-Options or CSP frame-ancestors"},
            description="No clickjacking protection headers found",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Missing Clickjacking Protection",
            type=VulnerabilityType.CLICKJACKING,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="The application does not use X-Frame-Options or Content-Security-Policy frame-ancestors directive to prevent clickjacking attacks.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Add X-Frame-Options header with DENY or SAMEORIGIN value, or use the Content-Security-Policy frame-ancestors directive.",
            references=[
                "https://owasp.org/www-community/attacks/Clickjacking",
                "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            ],
            cwe=1021,  # Improper Restriction of Rendered UI Layers or Frames
            tags={"clickjacking", "ui-redressing"},
        )


class CacheControlScanner(BaseScanner):
    """Scanner for checking cache control headers."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the cache control scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Checking cache control headers for {target.url}")
        vulnerabilities = []

        try:
            # Send request to the target
            response = self.scanner.send_request(target.url)
            
            # Check for missing or weak cache control
            cache_issues = self._check_cache_control(response.headers)
            if cache_issues:
                vuln = self._create_cache_control_vulnerability(target.url, cache_issues)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error checking cache control headers: {str(e)}", exc_info=True)
            return []

    def _check_cache_control(self, headers: Dict[str, str]) -> List[str]:
        """Check for cache control issues.

        Args:
            headers: HTTP headers

        Returns:
            List of cache control issues
        """
        issues = []
        
        # Check if Cache-Control header is present
        if "Cache-Control" not in headers:
            issues.append("Missing Cache-Control header")
        else:
            cache_control = headers["Cache-Control"].lower()
            directives = [d.strip() for d in cache_control.split(",")]
            
            # Check for private/no-store for sensitive pages
            if "private" not in directives and "no-store" not in directives:
                issues.append("Cache-Control does not include 'private' or 'no-store'")
            
            # Check for max-age
            max_age_pattern = re.compile(r"max-age=(\d+)")
            max_age_match = next((max_age_pattern.search(d) for d in directives if max_age_pattern.search(d)), None)
            
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age > 86400:  # More than 1 day
                    issues.append(f"Long max-age value: {max_age} seconds")
        
        # Check for Pragma header
        if "Pragma" not in headers or "no-cache" not in headers.get("Pragma", "").lower():
            issues.append("Missing 'Pragma: no-cache' header")
        
        # Check for Expires header
        if "Expires" not in headers:
            issues.append("Missing Expires header")
        
        return issues

    def _create_cache_control_vulnerability(
        self, url: HttpUrl, cache_issues: List[str]
    ) -> Vulnerability:
        """Create a vulnerability for cache control issues.

        Args:
            url: Target URL
            cache_issues: List of cache control issues

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="cache_headers",
            data=cache_issues,
            description=f"Cache control issues: {', '.join(cache_issues)}",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Insufficient Cache Control",
            type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            description="The application has insufficient cache control headers, which could lead to sensitive information being stored in browser caches or proxies.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Set appropriate Cache-Control, Pragma, and Expires headers to prevent caching of sensitive information.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses",
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching",
            ],
            cwe=525,  # Information Exposure Through Browser Caching
            tags={"caching", "information-disclosure"},
        )
