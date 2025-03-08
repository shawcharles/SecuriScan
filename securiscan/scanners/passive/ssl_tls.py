"""
SSL/TLS Scanner Module.

This module analyzes SSL/TLS configuration for security issues.
"""

import socket
import ssl
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

from pydantic import HttpUrl

from securiscan.core.result import Confidence, Evidence, Severity, ScanTarget, Vulnerability, VulnerabilityType
from securiscan.core.scanner import BaseScanner


class SSLTLSScanner(BaseScanner):
    """Scanner for checking SSL/TLS configuration."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the SSL/TLS scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Checking SSL/TLS configuration for {target.url}")
        vulnerabilities = []

        # Skip if not HTTPS
        if target.scheme != "https":
            self.logger.info(f"Skipping SSL/TLS checks for non-HTTPS URL: {target.url}")
            return vulnerabilities

        try:
            # Get hostname and port
            hostname = target.hostname.split(":")[0]  # Remove port if present
            port = target.port

            # Check certificate
            cert_issues = self._check_certificate(hostname, port)
            if cert_issues:
                vuln = self._create_certificate_vulnerability(target.url, cert_issues)
                vulnerabilities.append(vuln)

            # Check protocols and ciphers
            protocol_issues, cipher_issues, protocol_details = self._check_protocols_and_ciphers(hostname, port)
            
            if protocol_issues:
                vuln = self._create_protocol_vulnerability(target.url, protocol_issues, protocol_details)
                vulnerabilities.append(vuln)
                
            if cipher_issues:
                vuln = self._create_cipher_vulnerability(target.url, cipher_issues, protocol_details)
                vulnerabilities.append(vuln)

            # Check for other TLS/SSL issues
            other_issues = self._check_other_issues(hostname, port)
            if other_issues:
                vuln = self._create_other_issues_vulnerability(target.url, other_issues)
                vulnerabilities.append(vuln)

            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error checking SSL/TLS: {str(e)}", exc_info=True)
            return []

    def _check_certificate(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check the SSL certificate for issues.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            Dictionary of certificate issues
        """
        issues = {}
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to check expired/invalid certs too
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if not cert:
                        issues["no_certificate"] = "No certificate provided"
                        return issues
                    
                    # Parse dates
                    date_format = r'%b %d %H:%M:%S %Y %Z'
                    expiry_date = datetime.strptime(cert['notAfter'], date_format)
                    start_date = datetime.strptime(cert['notBefore'], date_format)
                    current_date = datetime.now()
                    
                    # Check if expired
                    if current_date > expiry_date:
                        issues["expired"] = {
                            "expired_on": expiry_date.isoformat(),
                            "days_expired": (current_date - expiry_date).days
                        }
                    
                    # Check if not yet valid
                    if current_date < start_date:
                        issues["not_yet_valid"] = {
                            "valid_from": start_date.isoformat(),
                            "days_until_valid": (start_date - current_date).days
                        }
                    
                    # Check if expiring soon (within 30 days)
                    days_to_expiry = (expiry_date - current_date).days
                    if 0 < days_to_expiry < 30:
                        issues["expiring_soon"] = {
                            "expires_on": expiry_date.isoformat(),
                            "days_remaining": days_to_expiry
                        }
                    
                    # Check subject alternative names
                    if 'subjectAltName' in cert:
                        alt_names = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                        
                        # Check if hostname is covered
                        if hostname not in alt_names and not any(self._is_wildcard_match(name, hostname) for name in alt_names):
                            issues["hostname_mismatch"] = {
                                "hostname": hostname,
                                "certificate_names": alt_names
                            }
                    else:
                        issues["no_san"] = "Certificate does not have Subject Alternative Names"
                    
                    # Check certificate chain (simplified)
                    try:
                        # Try with hostname verification
                        verify_context = ssl.create_default_context()
                        with socket.create_connection((hostname, port), timeout=10) as verify_sock:
                            with verify_context.wrap_socket(verify_sock, server_hostname=hostname) as verify_ssock:
                                # If we get here, the certificate chain is valid
                                pass
                    except ssl.SSLError as e:
                        if "certificate verify failed" in str(e):
                            issues["invalid_chain"] = str(e)
                    
                    # Get certificate information for evidence
                    issues["certificate_info"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "notBefore": cert['notBefore'],
                        "notAfter": cert['notAfter'],
                        "serialNumber": cert.get('serialNumber', 'Unknown'),
                    }
                    
                    return issues
        except Exception as e:
            issues["connection_error"] = str(e)
            return issues

    def _check_protocols_and_ciphers(self, hostname: str, port: int) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Check SSL/TLS protocols and ciphers.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            Tuple of (protocol issues, cipher issues, protocol details)
        """
        protocol_issues = {}
        cipher_issues = {}
        protocol_details = {}
        
        # Define protocols to check
        protocols = {
            ssl.PROTOCOL_TLSv1: "TLSv1.0",
            ssl.PROTOCOL_TLSv1_1: "TLSv1.1",
            ssl.PROTOCOL_TLSv1_2: "TLSv1.2",
        }
        
        # Check if TLSv1.3 is available (Python 3.7+)
        if hasattr(ssl, "PROTOCOL_TLSv1_3"):
            protocols[ssl.PROTOCOL_TLSv1_3] = "TLSv1.3"
        
        # Check if SSLv2 and SSLv3 are available (deprecated)
        if hasattr(ssl, "PROTOCOL_SSLv2"):
            protocols[ssl.PROTOCOL_SSLv2] = "SSLv2"
        if hasattr(ssl, "PROTOCOL_SSLv3"):
            protocols[ssl.PROTOCOL_SSLv3] = "SSLv3"
        
        # Check each protocol
        supported_protocols = []
        for protocol_const, protocol_name in protocols.items():
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.set_ciphers("ALL")
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        supported_protocols.append(protocol_name)
                        
                        # Get cipher information
                        cipher = ssock.cipher()
                        protocol_details[protocol_name] = {
                            "cipher_name": cipher[0],
                            "cipher_bits": cipher[2],
                            "cipher_version": cipher[1],
                        }
                        
                        # Check for weak ciphers
                        if self._is_weak_cipher(cipher[0]):
                            if protocol_name not in cipher_issues:
                                cipher_issues[protocol_name] = []
                            cipher_issues[protocol_name].append({
                                "cipher": cipher[0],
                                "bits": cipher[2],
                                "issue": "Weak cipher"
                            })
            except Exception:
                # Protocol not supported or error
                pass
        
        # Check for deprecated protocols
        deprecated_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
        for protocol in deprecated_protocols:
            if protocol in supported_protocols:
                protocol_issues[protocol] = "Deprecated protocol supported"
        
        # Check if modern protocols are supported
        modern_protocols = ["TLSv1.2", "TLSv1.3"]
        if not any(p in supported_protocols for p in modern_protocols):
            protocol_issues["no_modern_protocols"] = "No modern protocols (TLSv1.2+) supported"
        
        return protocol_issues, cipher_issues, protocol_details

    def _check_other_issues(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check for other SSL/TLS issues.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            Dictionary of other SSL/TLS issues
        """
        issues = {}
        
        # Check for BEAST vulnerability (requires TLSv1.0 with CBC ciphers)
        # This is a simplified check
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers("ALL:!NULL:!aNULL:!eNULL:!ADH:!AECDH:!MD5:!3DES:!DES:!RC4:!PSK:!SRP:!DSS")
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if "CBC" in cipher[0]:
                        issues["beast"] = "Potentially vulnerable to BEAST attack (TLSv1.0 with CBC cipher)"
        except Exception:
            # TLSv1.0 not supported or error
            pass
        
        # Check for POODLE vulnerability (requires SSLv3)
        # This is a simplified check
        if hasattr(ssl, "PROTOCOL_SSLv3"):
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as _:
                        issues["poodle"] = "Potentially vulnerable to POODLE attack (SSLv3 supported)"
            except Exception:
                # SSLv3 not supported or error
                pass
        
        # Check for secure renegotiation
        # This is a simplified check and may not be accurate
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check if secure renegotiation is supported
                    # This is not directly accessible in Python's ssl module
                    # A more accurate check would require using OpenSSL directly
                    pass
        except Exception as e:
            self.logger.debug(f"Error checking secure renegotiation: {str(e)}")
        
        return issues

    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """Check if a cipher is considered weak.

        Args:
            cipher_name: Cipher name

        Returns:
            True if the cipher is weak, False otherwise
        """
        weak_keywords = [
            "NULL", "EXPORT", "DES", "RC2", "RC4", "MD5", "anon", "ADH", "AECDH",
            "EXP", "EXP1024", "DES40", "DES-CBC", "3DES", "SEED"
        ]
        
        return any(keyword in cipher_name for keyword in weak_keywords)

    def _is_wildcard_match(self, pattern: str, hostname: str) -> bool:
        """Check if a hostname matches a wildcard pattern.

        Args:
            pattern: Wildcard pattern (e.g., *.example.com)
            hostname: Hostname to check

        Returns:
            True if the hostname matches the pattern, False otherwise
        """
        if not pattern.startswith("*."):
            return False
        
        domain = pattern[2:]  # Remove *. prefix
        return hostname.endswith(domain) and hostname.count(".") == domain.count(".") + 1

    def _create_certificate_vulnerability(
        self, url: HttpUrl, cert_issues: Dict[str, Any]
    ) -> Vulnerability:
        """Create a vulnerability for certificate issues.

        Args:
            url: Target URL
            cert_issues: Dictionary of certificate issues

        Returns:
            Vulnerability object
        """
        # Determine severity based on issues
        severity = Severity.LOW
        description_parts = []
        
        if "expired" in cert_issues:
            severity = Severity.HIGH
            description_parts.append(f"Certificate expired {cert_issues['expired']['days_expired']} days ago.")
        
        if "not_yet_valid" in cert_issues:
            severity = Severity.HIGH
            description_parts.append(f"Certificate not valid until {cert_issues['not_yet_valid']['days_until_valid']} days from now.")
        
        if "expiring_soon" in cert_issues:
            severity = Severity.MEDIUM
            description_parts.append(f"Certificate expires in {cert_issues['expiring_soon']['days_remaining']} days.")
        
        if "hostname_mismatch" in cert_issues:
            severity = Severity.HIGH
            description_parts.append("Certificate hostname mismatch.")
        
        if "no_san" in cert_issues:
            severity = Severity.MEDIUM
            description_parts.append("Certificate does not have Subject Alternative Names.")
        
        if "invalid_chain" in cert_issues:
            severity = Severity.HIGH
            description_parts.append("Invalid certificate chain.")
        
        if "no_certificate" in cert_issues:
            severity = Severity.HIGH
            description_parts.append("No SSL certificate provided.")
        
        if "connection_error" in cert_issues:
            severity = Severity.MEDIUM
            description_parts.append(f"Error checking certificate: {cert_issues['connection_error']}")
        
        # Create evidence
        evidence = Evidence(
            type="ssl_certificate",
            data=cert_issues,
            description="SSL/TLS certificate issues",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        description = "The SSL/TLS certificate has the following issues: " + " ".join(description_parts)
        
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="SSL/TLS Certificate Issues",
            type=VulnerabilityType.SSL_TLS_ISSUES,
            severity=severity,
            confidence=Confidence.HIGH,
            description=description,
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Ensure the certificate is valid, not expired, covers the correct hostname, and has a valid trust chain.",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://www.ssllabs.com/ssltest/",
            ],
            cwe=295,  # Improper Certificate Validation
            tags={"ssl", "tls", "certificate"},
        )

    def _create_protocol_vulnerability(
        self, url: HttpUrl, protocol_issues: Dict[str, Any], protocol_details: Dict[str, Any]
    ) -> Vulnerability:
        """Create a vulnerability for protocol issues.

        Args:
            url: Target URL
            protocol_issues: Dictionary of protocol issues
            protocol_details: Dictionary of protocol details

        Returns:
            Vulnerability object
        """
        # Determine severity based on issues
        severity = Severity.MEDIUM
        description_parts = []
        
        for protocol, issue in protocol_issues.items():
            if protocol in ["SSLv2", "SSLv3"]:
                severity = Severity.HIGH
            description_parts.append(f"{protocol}: {issue}")
        
        # Create evidence
        evidence = Evidence(
            type="ssl_protocols",
            data={
                "issues": protocol_issues,
                "details": protocol_details
            },
            description="SSL/TLS protocol issues",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        description = "The server supports insecure SSL/TLS protocols: " + " ".join(description_parts)
        
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Insecure SSL/TLS Protocols",
            type=VulnerabilityType.SSL_TLS_ISSUES,
            severity=severity,
            confidence=Confidence.HIGH,
            description=description,
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Disable outdated and insecure protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1) and enable only TLSv1.2 and TLSv1.3.",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://www.ssllabs.com/ssltest/",
            ],
            cwe=326,  # Inadequate Encryption Strength
            tags={"ssl", "tls", "protocols"},
        )

    def _create_cipher_vulnerability(
        self, url: HttpUrl, cipher_issues: Dict[str, Any], protocol_details: Dict[str, Any]
    ) -> Vulnerability:
        """Create a vulnerability for cipher issues.

        Args:
            url: Target URL
            cipher_issues: Dictionary of cipher issues
            protocol_details: Dictionary of protocol details

        Returns:
            Vulnerability object
        """
        # Determine severity based on issues
        severity = Severity.MEDIUM
        description_parts = []
        
        for protocol, ciphers in cipher_issues.items():
            cipher_names = [c["cipher"] for c in ciphers]
            description_parts.append(f"{protocol} uses weak ciphers: {', '.join(cipher_names)}")
        
        # Create evidence
        evidence = Evidence(
            type="ssl_ciphers",
            data={
                "issues": cipher_issues,
                "details": protocol_details
            },
            description="SSL/TLS cipher issues",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        description = "The server supports weak SSL/TLS ciphers: " + " ".join(description_parts)
        
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Weak SSL/TLS Ciphers",
            type=VulnerabilityType.SSL_TLS_ISSUES,
            severity=severity,
            confidence=Confidence.HIGH,
            description=description,
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Disable weak ciphers and enable only strong ciphers with perfect forward secrecy.",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://www.ssllabs.com/ssltest/",
            ],
            cwe=327,  # Use of a Broken or Risky Cryptographic Algorithm
            tags={"ssl", "tls", "ciphers"},
        )

    def _create_other_issues_vulnerability(
        self, url: HttpUrl, other_issues: Dict[str, Any]
    ) -> Vulnerability:
        """Create a vulnerability for other SSL/TLS issues.

        Args:
            url: Target URL
            other_issues: Dictionary of other SSL/TLS issues

        Returns:
            Vulnerability object
        """
        # Determine severity based on issues
        severity = Severity.MEDIUM
        description_parts = []
        
        for issue_type, issue_desc in other_issues.items():
            if issue_type in ["beast", "poodle"]:
                severity = Severity.HIGH
            description_parts.append(f"{issue_type}: {issue_desc}")
        
        # Create evidence
        evidence = Evidence(
            type="ssl_other_issues",
            data=other_issues,
            description="Other SSL/TLS issues",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        description = "The server has the following SSL/TLS vulnerabilities: " + " ".join(description_parts)
        
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="SSL/TLS Vulnerabilities",
            type=VulnerabilityType.SSL_TLS_ISSUES,
            severity=severity,
            confidence=Confidence.MEDIUM,
            description=description,
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Update the SSL/TLS configuration to mitigate known vulnerabilities.",
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://www.ssllabs.com/ssltest/",
            ],
            cwe=310,  # Cryptographic Issues
            tags={"ssl", "tls", "vulnerabilities"},
        )
