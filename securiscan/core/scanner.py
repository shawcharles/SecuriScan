"""
Scanner module for SecuriScan.

This module provides the core scanning functionality.
"""

import logging
import socket
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Type, Union
from urllib.parse import urlparse

import requests
from pydantic import HttpUrl

from securiscan.core.config import ScanConfig, ScanLevel
from securiscan.core.result import (
    ScanResult,
    ScanStatistics,
    ScanTarget,
    TechnologyInfo,
    Vulnerability,
)


class BaseScanner:
    """Base class for all scanners."""

    def __init__(self, scanner: 'Scanner'):
        """Initialize the scanner.

        Args:
            scanner: Main scanner instance
        """
        self.scanner = scanner
        self.config = scanner.config
        self.logger = logging.getLogger(f"securiscan.scanner.{self.get_id()}")

    @classmethod
    def get_id(cls) -> str:
        """Get the scanner ID.

        Returns:
            Scanner ID
        """
        return cls.__name__.lower()

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the scanner on the target.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found

        Raises:
            NotImplementedError: If the scanner does not implement this method
        """
        raise NotImplementedError("Scanners must implement the run method")


class Scanner:
    """Main scanner class for performing security assessments."""

    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize the scanner.

        Args:
            config: Scanner configuration
        """
        self.config = config or ScanConfig()
        self.logger = logging.getLogger("securiscan.scanner")
        self.session = requests.Session()
        self._registered_scanners: Dict[str, Type[BaseScanner]] = {}

    def scan(self, target_url: Union[str, HttpUrl]) -> ScanResult:
        """Perform a security scan on the target URL.

        Args:
            target_url: URL to scan

        Returns:
            Scan result
        """
        # Parse and validate the target URL
        parsed_url = urlparse(str(target_url))
        
        # Handle file:// URLs differently
        if parsed_url.scheme == "file":
            base_url = target_url  # Keep the full file:// URL
        else:
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Create scan statistics
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level=self.config.scan_level,
        )

        # Create scan target
        target = self._create_scan_target(base_url)

        # Run registered scanners
        vulnerabilities = []
        if self._registered_scanners:
            for scanner_id, scanner_class in self._registered_scanners.items():
                try:
                    self.logger.debug(f"Running scanner: {scanner_id}")
                    scanner = scanner_class(self)
                    scanner_vulnerabilities = scanner.run(target)
                    if scanner_vulnerabilities:
                        vulnerabilities.extend(scanner_vulnerabilities)
                except Exception as e:
                    self.logger.error(f"Error running scanner {scanner_id}: {str(e)}", exc_info=True)
        else:
            # Simulate scanning if no scanners are registered
            time.sleep(1)  # Simulate some work

        # Update statistics
        statistics.end_time = datetime.now()
        statistics.pages_scanned = 1
        statistics.requests_sent = 1
        statistics.vulnerabilities_found = len(vulnerabilities)

        # Create scan result
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            id=scan_id,
            target=target,
            vulnerabilities=vulnerabilities,
            statistics=statistics,
            scan_config=self.config.dict(),
            version="0.1.0",
        )

        self.logger.info(f"Scan completed: {len(result.vulnerabilities)} vulnerabilities found")

        return result

    def _create_scan_target(self, base_url: str) -> ScanTarget:
        """Create a scan target object with information about the target.

        Args:
            base_url: Base URL of the target

        Returns:
            ScanTarget object
        """
        parsed_url = urlparse(base_url)
        
        # Handle file:// URLs differently
        if parsed_url.scheme == "file":
            # For file:// URLs, use placeholder values for hostname, port, etc.
            target = ScanTarget(
                url=base_url,
                ip=None,
                hostname="localhost",
                port=0,
                scheme="file",
            )
        else:
            # For http(s):// URLs, use normal values
            hostname = parsed_url.netloc
            port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

            # Resolve IP address
            try:
                ip = socket.gethostbyname(hostname.split(":")[0])
            except socket.gaierror:
                ip = None

            # Create target object
            target = ScanTarget(
                url=base_url,
                ip=ip,
                hostname=hostname,
                port=port,
                scheme=parsed_url.scheme,
            )

        return target

    def register_scanner(self, scanner_class: Type[BaseScanner]) -> None:
        """Register a scanner class.

        Args:
            scanner_class: Scanner class to register
        """
        scanner_id = scanner_class.get_id()
        self._registered_scanners[scanner_id] = scanner_class
        self.logger.debug(f"Registered scanner: {scanner_id}")

    def send_request(self, url: str, method: str = "GET", **kwargs) -> requests.Response:
        """Send an HTTP request.

        Args:
            url: URL to request
            method: HTTP method
            **kwargs: Additional arguments for requests

        Returns:
            Response object
        """
        # Set default timeout
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.config.timeout

        # Send the request
        response = self.session.request(method, url, **kwargs)
        return response
