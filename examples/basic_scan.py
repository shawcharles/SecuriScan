#!/usr/bin/env python
"""
Basic Scan Example.

This example demonstrates how to use the SecuriScan framework to perform a basic security scan on a website.
"""

import argparse
import logging
import sys
from typing import List, Optional

from securiscan import (
    AuthConfig,
    AuthType,
    ProxyConfig,
    ScanConfig,
    ScanLevel,
    ScanResult,
    Scanner,
    Vulnerability,
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
    parser = argparse.ArgumentParser(description="SecuriScan Basic Example")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--level",
        choices=["passive", "standard", "aggressive"],
        default="standard",
        help="Scan level (default: standard)",
    )
    parser.add_argument(
        "--output",
        help="Output file for the report (HTML format)",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy URL (e.g., http://127.0.0.1:8080)",
    )
    parser.add_argument(
        "--username",
        help="Username for authentication",
    )
    parser.add_argument(
        "--password",
        help="Password for authentication",
    )
    parser.add_argument(
        "--auth-type",
        choices=["basic", "digest", "ntlm", "form"],
        default="basic",
        help="Authentication type (default: basic)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads to use (default: 10)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=3,
        help="Maximum crawl depth (default: 3)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    return parser.parse_args()


def create_scan_config(args: argparse.Namespace) -> ScanConfig:
    """Create scan configuration from arguments.

    Args:
        args: Command-line arguments

    Returns:
        Scan configuration
    """
    # Create authentication configuration if credentials are provided
    auth_config = None
    if args.username and args.password:
        auth_type = {
            "basic": AuthType.BASIC,
            "digest": AuthType.DIGEST,
            "ntlm": AuthType.NTLM,
            "form": AuthType.FORM,
        }[args.auth_type]
        
        auth_config = AuthConfig(
            username=args.username,
            password=args.password,
            auth_type=auth_type,
        )
    
    # Create proxy configuration if proxy is provided
    proxy_config = None
    if args.proxy:
        proxy_config = ProxyConfig(
            url=args.proxy,
        )
    
    # Create scan configuration
    scan_level = {
        "passive": ScanLevel.PASSIVE,
        "standard": ScanLevel.STANDARD,
        "aggressive": ScanLevel.AGGRESSIVE,
    }[args.level]
    
    return ScanConfig(
        scan_level=scan_level,
        max_depth=args.max_depth,
        threads=args.threads,
        timeout=args.timeout,
        auth_config=auth_config,
        proxy_config=proxy_config,
    )


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
        config = create_scan_config(args)
        
        # Create scanner
        scanner = Scanner(config)
        
        # Run scan
        print(f"Scanning {args.url} with {args.level} scan level...")
        result = scanner.scan(args.url)
        
        # Print results
        print("\nScan completed successfully.")
        print(f"Scan duration: {result.duration:.2f} seconds")
        print(f"Pages scanned: {result.statistics.pages_scanned}")
        print(f"Requests sent: {result.statistics.requests_sent}")
        
        # Print vulnerabilities
        print("\nVulnerabilities:")
        print_vulnerabilities(result.vulnerabilities)
        
        # Generate report if output file is specified
        if args.output:
            result.generate_report(args.output, "html")
            print(f"\nReport saved to {args.output}")
        
        return 0
        
    except Exception as e:
        logging.error(f"Error: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
