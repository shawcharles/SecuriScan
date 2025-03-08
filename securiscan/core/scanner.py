"""
Scanner module for SecuriScan.

This module provides the core scanning functionality.
"""

import importlib
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
from securiscan.core.exceptions import ConfigurationError, ConnectionError, ScanError
from securiscan.core.result import (
    ScanResult,
    ScanStatistics,
    ScanTarget,
    TechnologyInfo,
    Vulnerability,
)


class Scanner:
    """Main scanner class for performing security assessments."""

    def __init__(self, config: Optional[ScanConfig] = None):
        """Initialize the scanner.

        Args:
            config: Scanner configuration
        """
        self.config = config or ScanConfig()
        self.logger = logging.getLogger("securiscan.scanner")
        self.session = self._create_session()
        self._registered_scanners: Dict[str, Type["BaseScanner"]] = {}
        self._discovered_urls: Set[str] = set()
        self._scanned_urls: Set[str] = set()
        self._request_count = 0
        self._last_request_time = 0.0
        self._vulnerabilities: List[Vulnerability] = []

        # Register built-in scanners
        self._register_built_in_scanners()

    def scan(self, target_url: Union[str, HttpUrl]) -> ScanResult:
        """Perform a security scan on the target URL.

        Args:
            target_url: URL to scan

        Returns:
            Scan result

        Raises:
            ConnectionError: If there is an error connecting to the target
            ScanError: If there is an error during scanning
        """
        # Reset state for new scan
        self._discovered_urls = set()
        self._scanned_urls = set()
        self._request_count = 0
        self._vulnerabilities = []

        # Parse and validate the target URL
        try:
            parsed_url = urlparse(str(target_url))
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        except Exception as e:
            raise ConfigurationError(f"Invalid target URL: {str(e)}")

        # Create scan statistics
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level=self.config.scan_level,
        )

        # Create scan target
        target = self._create_scan_target(base_url)

        # Add the initial URL to the discovered URLs
        self._discovered_urls.add(str(target_url))

        # Run the scan
        try:
            self.logger.info(f"Starting scan of {target_url} with level {self.config.scan_level}")
            self._run_scanners(target)
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}", exc_info=True)
            raise ScanError(f"Scan failed: {str(e)}")
        finally:
            # Update statistics
            statistics.end_time = datetime.now()
            statistics.urls_discovered = len(self._discovered_urls)
            statistics.urls_scanned = len(self._scanned_urls)
            statistics.requests_sent = self._request_count
            statistics.vulnerabilities_found = len(self._vulnerabilities)

        # Create scan result
        scan_id = str(uuid.uuid4())
        result = ScanResult(
            id=scan_id,
            target=target,
            vulnerabilities=self._vulnerabilities,
            statistics=statistics,
            scan_config=self.config.dict(),
            version="0.1.0",  # TODO: Get from package version
        )

        # Calculate risk score and level
        result.update_risk_assessment()

        self.logger.info(
            f"Scan completed: {len(self._vulnerabilities)} vulnerabilities found, "
            f"risk level: {result.risk_level}"
        )

        return result

    def _create_session(self) -> requests.Session:
        """Create a requests session with the configured settings.

        Returns:
            Configured requests session
        """
        session = requests.Session()

        # Set default headers
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Pragma": "no-cache",
            "Cache-Control": "no-cache",
        })

        # Add custom headers
        if self.config.headers:
            session.headers.update(self.config.headers)

        # Add cookies
        if self.config.cookies:
            for name, value in self.config.cookies.items():
                session.cookies.set(name, value)

        # Configure authentication
        if self.config.auth:
            if self.config.auth.type == "basic":
                session.auth = (self.config.auth.username, self.config.auth.password)
            elif self.config.auth.type == "bearer":
                session.headers["Authorization"] = f"Bearer {self.config.auth.token}"
            elif self.config.auth.type == "custom" and self.config.auth.custom_auth_header:
                session.headers[self.config.auth.custom_auth_header] = self.config.auth.custom_auth_value

        # Configure proxy
        if self.config.proxy:
            proxy_url = f"{self.config.proxy.type}://"
            if self.config.proxy.username and self.config.proxy.password:
                proxy_url += f"{self.config.proxy.username}:{self.config.proxy.password}@"
            proxy_url += f"{self.config.proxy.host}:{self.config.proxy.port}"
            session.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }

        return session

    def _create_scan_target(self, base_url: str) -> ScanTarget:
        """Create a scan target object with information about the target.

        Args:
            base_url: Base URL of the target

        Returns:
            ScanTarget object

        Raises:
            ConnectionError: If there is an error connecting to the target
        """
        parsed_url = urlparse(base_url)
        hostname = parsed_url.netloc
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

        # Resolve IP address
        try:
            ip = socket.gethostbyname(hostname.split(":")[0])
        except socket.gaierror as e:
            self.logger.warning(f"Could not resolve hostname: {str(e)}")
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

    def _register_built_in_scanners(self) -> None:
        """Register all built-in scanner modules."""
        # This will be populated with actual scanner modules
        scanner_modules = [
            "securiscan.scanners.passive.headers",
            "securiscan.scanners.passive.content",
            "securiscan.scanners.passive.ssl_tls",
            "securiscan.scanners.passive.tech_detection",
            "securiscan.scanners.active.injection",
            "securiscan.scanners.active.xss",
            "securiscan.scanners.active.csrf",
            "securiscan.scanners.active.auth",
        ]

        for module_name in scanner_modules:
            try:
                # For now, just log that we would import these modules
                # In a real implementation, we would import and register them
                self.logger.debug(f"Would register scanner module: {module_name}")
                
                # Uncomment this when the modules are actually implemented
                # module = importlib.import_module(module_name)
                # for name in dir(module):
                #     obj = getattr(module, name)
                #     if (isinstance(obj, type) and issubclass(obj, BaseScanner) 
                #             and obj is not BaseScanner):
                #         self.register_scanner(obj)
            except ImportError as e:
                self.logger.warning(f"Could not import scanner module {module_name}: {str(e)}")

    def register_scanner(self, scanner_class: Type["BaseScanner"]) -> None:
        """Register a scanner class.

        Args:
            scanner_class: Scanner class to register
        """
        scanner_id = scanner_class.get_id()
        self._registered_scanners[scanner_id] = scanner_class
        self.logger.debug(f"Registered scanner: {scanner_id}")

    def _run_scanners(self, target: ScanTarget) -> None:
        """Run all registered scanners on the target.

        Args:
            target: Scan target
        """
        # Determine which scanners to run based on scan level
        scanners_to_run = self._get_scanners_for_level()

        # Run each scanner
        for scanner_id, scanner_class in scanners_to_run.items():
            if self.config.enabled_modules and scanner_id not in self.config.enabled_modules:
                self.logger.debug(f"Skipping disabled scanner: {scanner_id}")
                continue

            if scanner_id in self.config.disabled_modules:
                self.logger.debug(f"Skipping disabled scanner: {scanner_id}")
                continue

            try:
                self.logger.info(f"Running scanner: {scanner_id}")
                scanner = scanner_class(self)
                vulnerabilities = scanner.run(target)
                if vulnerabilities:
                    self.logger.info(f"Scanner {scanner_id} found {len(vulnerabilities)} vulnerabilities")
                    self._vulnerabilities.extend(vulnerabilities)
            except Exception as e:
                self.logger.error(f"Error running scanner {scanner_id}: {str(e)}", exc_info=True)

    def _get_scanners_for_level(self) -> Dict[str, Type["BaseScanner"]]:
        """Get the scanners to run for the current scan level.

        Returns:
            Dictionary of scanner IDs to scanner classes
        """
        # In a real implementation, we would filter scanners based on their level
        # For now, return all registered scanners
        return self._registered_scanners

    def send_request(
        self, url: str, method: str = "GET", **kwargs
    ) -> requests.Response:
        """Send an HTTP request with rate limiting and tracking.

        Args:
            url: URL to request
            method: HTTP method
            **kwargs: Additional arguments for requests

        Returns:
            Response object

        Raises:
            ConnectionError: If there is an error connecting to the target
        """
        # Apply rate limiting if enabled
        if self.config.smart_rate_limiting:
            self._apply_rate_limiting()

        # Set default timeout
        if "timeout" not in kwargs:
            kwargs["timeout"] = self.config.timeout

        # Set SSL verification
        kwargs["verify"] = self.config.verify_ssl

        # Set redirect behavior
        kwargs["allow_redirects"] = self.config.follow_redirects
        if self.config.follow_redirects:
            kwargs["max_redirects"] = self.config.max_redirects

        # Send the request
        try:
            self._last_request_time = time.time()
            response = self.session.request(method, url, **kwargs)
            self._request_count += 1
            return response
        except requests.RequestException as e:
            raise ConnectionError(f"Error connecting to {url}: {str(e)}", url=url)

    def _apply_rate_limiting(self) -> None:
        """Apply rate limiting based on configuration."""
        if self._last_request_time == 0:
            return

        # Calculate time since last request
        elapsed = time.time() - self._last_request_time
        min_interval = 1.0 / self.config.max_requests_per_second

        # Sleep if we're sending requests too quickly
        if elapsed < min_interval:
            sleep_time = min_interval - elapsed
            time.sleep(sleep_time)

    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the results.

        Args:
            vulnerability: Vulnerability to add
        """
        self._vulnerabilities.append(vulnerability)

    def discover_url(self, url: str) -> None:
        """Add a URL to the list of discovered URLs.

        Args:
            url: URL to add
        """
        self._discovered_urls.add(url)

    def mark_url_scanned(self, url: str) -> None:
        """Mark a URL as scanned.

        Args:
            url: URL to mark
        """
        self._scanned_urls.add(url)


class BaseScanner:
    """Base class for all scanners."""

    def __init__(self, scanner: Scanner):
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

    @classmethod
    def get_name(cls) -> str:
        """Get the scanner name.

        Returns:
            Scanner name
        """
        return cls.__name__

    @classmethod
    def get_description(cls) -> str:
        """Get the scanner description.

        Returns:
            Scanner description
        """
        return cls.__doc__ or "No description available"

    @classmethod
    def get_min_scan_level(cls) -> ScanLevel:
        """Get the minimum scan level required for this scanner.

        Returns:
            Minimum scan level
        """
        return ScanLevel.PASSIVE

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
