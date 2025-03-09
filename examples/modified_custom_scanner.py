#!/usr/bin/env python
"""
Modified Custom Scanner Example.

This example demonstrates how to create a custom scanner module for the SecuriScan framework,
with proper report generation using the ReportGenerator class.
"""

import argparse
import logging
import re
import sys
import uuid
from datetime import datetime
from typing import List, Optional

import requests
from bs4 import BeautifulSoup

from securiscan import (
    BaseScanner,
    Confidence,
    Evidence,
    ScanConfig,
    ScanLevel,
    ScanResult,
    ScanTarget,
    Scanner,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from securiscan.reporting.generator import ReportGenerator


class CustomScanner(BaseScanner):
    """Custom scanner for detecting email addresses in web pages."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the custom scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Running custom email scanner on {target.url}")
        vulnerabilities = []

        try:
            # Handle file:// URLs differently
            if target.url.startswith("file:///"):
                # Read the file directly
                file_path = target.url[8:]  # Remove file:/// prefix
                self.logger.debug(f"Reading file: {file_path}")
                with open(file_path, "r", encoding="utf-8") as f:
                    html_content = f.read()
            else:
                # Send request to the target
                response = self.scanner.send_request(target.url)
                html_content = response.text
            
            # Parse HTML
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Extract text content
            text_content = soup.get_text()
            
            # Find email addresses
            email_addresses = self._find_email_addresses(text_content)
            
            # Create vulnerability if email addresses are found
            if email_addresses:
                vuln = self._create_email_disclosure_vulnerability(target.url, email_addresses)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error in custom scanner: {str(e)}", exc_info=True)
            return []

    def _find_email_addresses(self, text: str) -> List[str]:
        """Find email addresses in text.

        Args:
            text: Text to search

        Returns:
            List of email addresses
        """
        # Regular expression for email addresses
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        
        # Find all matches
        email_addresses = re.findall(email_pattern, text)
        
        # Remove duplicates
        return list(set(email_addresses))

    def _create_email_disclosure_vulnerability(
        self,
        url: str,
        email_addresses: List[str],
    ) -> Vulnerability:
        """Create a vulnerability for email address disclosure.

        Args:
            url: Target URL
            email_addresses: List of email addresses

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="email_disclosure",
            data=email_addresses,
            description=f"Found {len(email_addresses)} email addresses",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Email Address Disclosure",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=f"The page contains {len(email_addresses)} email addresses that could be harvested by spammers or used for social engineering attacks.",
            url=url,
            path=url.path if hasattr(url, "path") else "",
            evidence=[evidence],
            remediation="Consider obfuscating email addresses or using contact forms instead of displaying email addresses directly on the page.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
            ],
            cwe=200,  # CWE-200: Information Exposure
            tags={"information-disclosure", "email", "privacy"},
        )


def setup_logging() -> None:
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description="SecuriScan Modified Custom Scanner Example")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--output",
        help="Output file for the report (HTML format)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    return parser.parse_args()


def print_vulnerabilities(vulnerabilities: List[Vulnerability]) -> None:
    """Print vulnerabilities to the console.

    Args:
        vulnerabilities: List of vulnerabilities
    """
    if not vulnerabilities:
        print("No vulnerabilities found.")
        return
    
    print(f"Found {len(vulnerabilities)} vulnerabilities:")
    print("-" * 80)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"{i}. [{vuln.severity}] {vuln.name}")
        print(f"   URL: {vuln.url}")
        print(f"   Description: {vuln.description}")
        
        # Print evidence
        if vuln.evidence:
            evidence = vuln.evidence[0]
            if evidence.type == "email_disclosure":
                print("   Email addresses found:")
                for email in evidence.data[:5]:  # Show first 5 emails
                    print(f"     - {email}")
                if len(evidence.data) > 5:
                    print(f"     - ... and {len(evidence.data) - 5} more")
        
        print(f"   Remediation: {vuln.remediation}")
        print("-" * 80)


def main() -> int:
    """Run the example.

    Returns:
        Exit code
    """
    # Set up logging
    setup_logging()
    
    # Parse arguments
    args = parse_arguments()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Create scan configuration
        config = ScanConfig(
            scan_level=ScanLevel.PASSIVE,
            max_depth=1,
            threads=1,
            timeout=30,
        )
        
        # Create scanner
        scanner = Scanner(config)
        
        # Register custom scanner
        scanner.register_scanner(CustomScanner)
        
        # Run scan
        print(f"Scanning {args.url} with custom email scanner...")
        result = scanner.scan(args.url)
        
        # Print results
        print("\nScan completed successfully.")
        print(f"Scan duration: {result.duration:.2f} seconds")
        
        # Print vulnerabilities
        print("\nVulnerabilities:")
        print_vulnerabilities(result.vulnerabilities)
        
        # Generate report if output file is specified
        if args.output:
            # Use ReportGenerator instead of result.generate_report
            report_generator = ReportGenerator(result)
            report_generator.generate(args.output, "html")
            print(f"\nReport saved to {args.output}")
        
        return 0
        
    except Exception as e:
        logging.error(f"Error: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
