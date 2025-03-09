"""
Command-line interface for SecuriScan.

This module provides the command-line interface for the SecuriScan framework.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from securiscan import Scanner, ScanConfig, ScanLevel, __version__
from securiscan.core.exceptions import SecuriScanError
from securiscan.core.monitor import Monitor

# Create Typer app
app = typer.Typer(
    name="securiscan",
    help="Professional Web Security Testing Framework",
    add_completion=False,
)

# Create console for rich output
console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Set up logging configuration.

    Args:
        verbose: Whether to enable verbose logging
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )


def print_banner() -> None:
    """Print the SecuriScan banner."""
    banner = r"""
   _____                      _  _____                 
  / ____|                    (_)/ ____|                
 | (___   ___  ___ _   _ _ __ _| (___   ___ __ _ _ __  
  \___ \ / _ \/ __| | | | '__| |\___ \ / __/ _` | '_ \ 
  ____) |  __/ (__| |_| | |  | |____) | (_| (_| | | | |
 |_____/ \___|\___|\__,_|_|  |_|_____/ \___\__,_|_| |_|
                                                       
    """
    console.print(banner, style="bold blue")
    console.print(f"[bold]SecuriScan v{__version__}[/bold] - Professional Web Security Testing Framework")
    console.print("MIT License - Use responsibly and only on authorized targets\n")


@app.callback()
def callback(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Don't display the banner"),
) -> None:
    """SecuriScan - Professional Web Security Testing Framework."""
    # Set up logging
    setup_logging(verbose)
    
    # Print banner
    if not no_banner:
        print_banner()


@app.command("scan")
def scan_command(
    target: str = typer.Argument(..., help="Target URL to scan"),
    output: str = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option(
        "html", "--format", "-f", help="Output format (html, json, csv, pdf)"
    ),
    level: str = typer.Option(
        "standard", "--level", "-l", help="Scan level (passive, light, standard, aggressive)"
    ),
    modules: str = typer.Option(
        None, "--modules", "-m", help="Comma-separated list of modules to enable"
    ),
    disable_modules: str = typer.Option(
        None, "--disable", "-d", help="Comma-separated list of modules to disable"
    ),
    timeout: int = typer.Option(30, "--timeout", "-t", help="Request timeout in seconds"),
    threads: int = typer.Option(10, "--threads", help="Number of threads to use"),
    delay: float = typer.Option(0.0, "--delay", help="Delay between requests in seconds"),
    user_agent: str = typer.Option(
        None, "--user-agent", "-ua", help="Custom User-Agent string"
    ),
    cookies: str = typer.Option(
        None, "--cookies", "-c", help="Cookies to include in requests (format: name=value;name2=value2)"
    ),
    headers: str = typer.Option(
        None, "--headers", "-H", help="Custom headers (format: name=value;name2=value2)"
    ),
    auth: str = typer.Option(
        None, "--auth", "-a", help="Authentication credentials (format: username:password)"
    ),
    auth_type: str = typer.Option(
        "basic", "--auth-type", help="Authentication type (basic, digest, bearer)"
    ),
    no_verify_ssl: bool = typer.Option(
        False, "--no-verify-ssl", help="Disable SSL certificate verification"
    ),
    include_subdomains: bool = typer.Option(
        False, "--include-subdomains", help="Include subdomains in the scan"
    ),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth"),
    max_urls: int = typer.Option(1000, "--max-urls", help="Maximum number of URLs to scan"),
    browser: bool = typer.Option(
        False, "--browser", "-b", help="Enable headless browser for client-side testing"
    ),
    screenshot: bool = typer.Option(
        False, "--screenshot", "-s", help="Take screenshots as evidence (requires --browser)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
) -> None:
    """Perform a security scan on a target URL."""
    try:
        # Set up logging
        setup_logging(verbose)
        
        # Parse scan level
        try:
            scan_level = ScanLevel(level.lower())
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid scan level: {level}")
            console.print(f"Valid levels: {', '.join([l.value for l in ScanLevel])}")
            sys.exit(1)
        
        # Parse modules
        enabled_modules = set(modules.split(",")) if modules else None
        disabled_modules = set(disable_modules.split(",")) if disable_modules else set()
        
        # Parse cookies
        cookies_dict = {}
        if cookies:
            try:
                for cookie in cookies.split(";"):
                    name, value = cookie.strip().split("=", 1)
                    cookies_dict[name] = value
            except ValueError:
                console.print("[bold red]Error:[/bold red] Invalid cookie format. Use name=value;name2=value2")
                sys.exit(1)
        
        # Parse headers
        headers_dict = {}
        if headers:
            try:
                for header in headers.split(";"):
                    name, value = header.strip().split("=", 1)
                    headers_dict[name] = value
            except ValueError:
                console.print("[bold red]Error:[/bold red] Invalid header format. Use name=value;name2=value2")
                sys.exit(1)
        
        # Create scan configuration
        config = ScanConfig(
            scan_level=scan_level,
            max_depth=max_depth,
            max_urls=max_urls,
            threads=threads,
            timeout=timeout,
            delay=delay,
            user_agent=user_agent,
            verify_ssl=not no_verify_ssl,
            headers=headers_dict,
            cookies=cookies_dict,
            include_subdomains=include_subdomains,
            enabled_modules=enabled_modules,
            disabled_modules=disabled_modules,
            use_browser=browser,
            screenshot_evidence=screenshot,
        )
        
        # Set up authentication if provided
        if auth:
            if auth_type.lower() == "basic":
                try:
                    username, password = auth.split(":", 1)
                    config.auth = {
                        "type": "basic",
                        "username": username,
                        "password": password,
                    }
                except ValueError:
                    console.print("[bold red]Error:[/bold red] Invalid auth format. Use username:password")
                    sys.exit(1)
            elif auth_type.lower() == "bearer":
                config.auth = {
                    "type": "bearer",
                    "token": auth,
                }
            else:
                console.print(f"[bold red]Error:[/bold red] Unsupported auth type: {auth_type}")
                sys.exit(1)
        
        # Create scanner
        scanner = Scanner(config)
        
        # Run scan with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}[/bold blue]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {target}...", total=None)
            
            # Run scan
            start_time = time.time()
            result = scanner.scan(target)
            elapsed_time = time.time() - start_time
            
            progress.update(task, completed=True, description=f"Scan completed in {elapsed_time:.2f} seconds")
        
        # Display summary
        console.print("\n[bold]Scan Summary:[/bold]")
        console.print(f"Target: {result.target.url}")
        console.print(f"Risk Level: [bold]{result.risk_level}[/bold] ({result.risk_score:.1f}/100)")
        console.print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        console.print(f"Scan Duration: {result.statistics.duration_seconds:.2f} seconds")
        console.print(f"URLs Discovered: {result.statistics.urls_discovered}")
        console.print(f"URLs Scanned: {result.statistics.urls_scanned}")
        console.print(f"Requests Sent: {result.statistics.requests_sent}")
        
        # Display vulnerabilities by severity
        if result.vulnerabilities:
            table = Table(title="Vulnerabilities by Severity")
            table.add_column("Severity", style="bold")
            table.add_column("Count")
            
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            
            for vuln in result.vulnerabilities:
                severity_counts[vuln.severity.lower()] += 1
            
            severity_styles = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "info": "blue",
            }
            
            for severity, count in severity_counts.items():
                if count > 0:
                    table.add_row(
                        severity.upper(),
                        str(count),
                        style=severity_styles.get(severity, "")
                    )
            
            console.print(table)
        
        # Generate report if output file specified
        if output:
            output_path = result.generate_report(output, format)
            console.print(f"\nReport saved to: [bold]{output_path}[/bold]")
        
    except SecuriScanError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
        logging.exception("Unexpected error")
        sys.exit(1)


@app.command("monitor")
def monitor_command(
    target: List[str] = typer.Argument(..., help="Target URL(s) to monitor"),
    interval: float = typer.Option(
        24.0, "--interval", "-i", help="Monitoring interval in hours"
    ),
    notify: List[str] = typer.Option(
        None, "--notify", "-n", help="Email addresses to notify"
    ),
    level: str = typer.Option(
        "standard", "--level", "-l", help="Scan level (passive, light, standard, aggressive)"
    ),
    output_dir: str = typer.Option(
        "./reports", "--output-dir", "-o", help="Directory to save reports"
    ),
    format: str = typer.Option(
        "html", "--format", "-f", help="Report format (html, json, csv, pdf)"
    ),
    run_immediately: bool = typer.Option(
        True, "--run-now", help="Run the first scan immediately"
    ),
) -> None:
    """Continuously monitor target URL(s) for security issues."""
    try:
        # Parse scan level
        try:
            scan_level = ScanLevel(level.lower())
        except ValueError:
            console.print(f"[bold red]Error:[/bold red] Invalid scan level: {level}")
            console.print(f"Valid levels: {', '.join([l.value for l in ScanLevel])}")
            sys.exit(1)
        
        # Create scan configuration
        config = ScanConfig(
            scan_level=scan_level,
        )
        
        # Create output directory if it doesn't exist
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create monitor
        monitor = Monitor(
            targets=target,
            interval_hours=interval,
            scan_config=config,
            notify=notify,
        )
        
        # Register callbacks
        def on_complete(target: str, result: any) -> None:
            """Callback when a scan completes."""
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{output_dir_path / timestamp}_{target.replace('://', '_').replace('/', '_')}.{format}"
            result.generate_report(filename, format)
            console.print(f"Scan completed for {target}: {len(result.vulnerabilities)} vulnerabilities found")
            console.print(f"Report saved to: {filename}")
        
        def on_error(target: str, error: Exception) -> None:
            """Callback when a scan errors."""
            console.print(f"[bold red]Error scanning {target}:[/bold red] {str(error)}")
        
        monitor.on("on_complete", on_complete)
        monitor.on("on_error", on_error)
        
        # Start monitoring
        console.print(f"Starting monitoring of {len(target)} target(s) every {interval} hours")
        console.print("Press Ctrl+C to stop monitoring")
        
        monitor.start(run_immediately=run_immediately)
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\nStopping monitoring...")
            monitor.stop()
            console.print("Monitoring stopped")
        
    except SecuriScanError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Unexpected error:[/bold red] {str(e)}")
        logging.exception("Unexpected error")
        sys.exit(1)


@app.command("list-modules")
def list_modules_command() -> None:
    """List available scanner modules."""
    try:
        # Create scanner with default configuration
        scanner = Scanner()
        
        # Get registered scanners
        scanners = scanner._registered_scanners
        
        if not scanners:
            console.print("[yellow]No scanner modules registered.[/yellow]")
            console.print("This may be because the scanner modules are not yet implemented.")
            return
        
        # Display modules
        table = Table(title="Available Scanner Modules")
        table.add_column("ID", style="bold")
        table.add_column("Name")
        table.add_column("Description")
        table.add_column("Min Level")
        
        for scanner_id, scanner_class in sorted(scanners.items()):
            table.add_row(
                scanner_id,
                scanner_class.get_name(),
                scanner_class.get_description(),
                scanner_class.get_min_scan_level().value,
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


@app.command("version")
def version_command() -> None:
    """Display version information."""
    console.print(f"SecuriScan v{__version__}")


def main() -> None:
    """Main entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
