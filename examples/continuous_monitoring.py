#!/usr/bin/env python
"""
Modified Continuous Monitoring Example.

This example demonstrates how to use the SecuriScan framework to continuously monitor a website for security issues,
with proper report generation using the ReportGenerator class.
"""

import argparse
import logging
import os
import sys
import time
from typing import List, Optional

from securiscan import (
    AuthConfig,
    AuthType,
    Monitor,
    MonitorConfig,
    NotificationConfig,
    ProxyConfig,
    ScanConfig,
    ScanLevel,
    Vulnerability,
)
from securiscan.reporting.generator import ReportGenerator


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
    parser = argparse.ArgumentParser(description="SecuriScan Modified Continuous Monitoring Example")
    parser.add_argument("url", help="Target URL to monitor")
    parser.add_argument(
        "--interval",
        type=int,
        default=3600,
        help="Monitoring interval in seconds (default: 3600)",
    )
    parser.add_argument(
        "--level",
        choices=["passive", "standard", "aggressive"],
        default="passive",
        help="Scan level (default: passive)",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)",
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
        "--email",
        help="Email address for notifications",
    )
    parser.add_argument(
        "--smtp-server",
        default="smtp.gmail.com",
        help="SMTP server for email notifications (default: smtp.gmail.com)",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=587,
        help="SMTP port for email notifications (default: 587)",
    )
    parser.add_argument(
        "--smtp-username",
        help="SMTP username for email notifications",
    )
    parser.add_argument(
        "--smtp-password",
        help="SMTP password for email notifications",
    )
    parser.add_argument(
        "--webhook-url",
        help="Webhook URL for notifications (e.g., Slack, Discord)",
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
        default=5,
        help="Number of threads to use (default: 5)",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum crawl depth (default: 2)",
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


def create_notification_config(args: argparse.Namespace) -> Optional[NotificationConfig]:
    """Create notification configuration from arguments.

    Args:
        args: Command-line arguments

    Returns:
        Notification configuration or None if no notification methods are configured
    """
    # Check if any notification methods are configured
    if not args.email and not args.webhook_url:
        return None
    
    # Create notification configuration
    notification_config = NotificationConfig()
    
    # Configure email notifications
    if args.email:
        if not args.smtp_username or not args.smtp_password:
            logging.warning("SMTP username and password are required for email notifications")
        else:
            notification_config.enable_email(
                recipient_email=args.email,
                smtp_server=args.smtp_server,
                smtp_port=args.smtp_port,
                smtp_username=args.smtp_username,
                smtp_password=args.smtp_password,
            )
    
    # Configure webhook notifications
    if args.webhook_url:
        notification_config.enable_webhook(
            webhook_url=args.webhook_url,
        )
    
    return notification_config


def create_monitor_config(args: argparse.Namespace) -> MonitorConfig:
    """Create monitor configuration from arguments.

    Args:
        args: Command-line arguments

    Returns:
        Monitor configuration
    """
    # Create scan configuration
    scan_config = create_scan_config(args)
    
    # Create notification configuration
    notification_config = create_notification_config(args)
    
    # Create monitor configuration
    return MonitorConfig(
        interval=args.interval,
        scan_config=scan_config,
        notification_config=notification_config,
        report_dir=args.output_dir,
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
        # Create monitor configuration
        config = create_monitor_config(args)
        
        # Create monitor
        monitor = Monitor(config)
        
        # Define callback function for scan results
        def on_scan_complete(result):
            print("\nScan completed successfully.")
            print(f"Scan duration: {result.duration:.2f} seconds")
            print(f"Pages scanned: {result.statistics.pages_scanned}")
            print(f"Requests sent: {result.statistics.requests_sent}")
            
            # Print vulnerabilities
            print("\nVulnerabilities:")
            print_vulnerabilities(result.vulnerabilities)
            
            # Generate report
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_filename = f"{args.output_dir}/scan_{timestamp}.html"
            
            # Create directory if it doesn't exist
            os.makedirs(args.output_dir, exist_ok=True)
            
            # Use ReportGenerator instead of result.generate_report
            report_generator = ReportGenerator(result)
            report_generator.generate(report_filename, "html")
            print(f"\nReport saved to {report_filename}")
            
            # Print next scan time
            next_scan_time = time.time() + args.interval
            next_scan_time_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(next_scan_time))
            print(f"\nNext scan scheduled at: {next_scan_time_str}")
        
        # Start monitoring
        print(f"Starting continuous monitoring of {args.url} with {args.level} scan level...")
        print(f"Scan interval: {args.interval} seconds")
        print(f"Reports will be saved to: {args.output_dir}")
        
        if config.notification_config:
            print("Notifications enabled:")
            if config.notification_config.email_enabled:
                print(f"  - Email: {args.email}")
            if config.notification_config.webhook_enabled:
                print(f"  - Webhook: {args.webhook_url}")
        
        print("\nPress Ctrl+C to stop monitoring.")
        
        # Start monitoring
        monitor.start(args.url, on_scan_complete)
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            monitor.stop()
            print("Monitoring stopped.")
        
        return 0
        
    except Exception as e:
        logging.error(f"Error: {str(e)}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
