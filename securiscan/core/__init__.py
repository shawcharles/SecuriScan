"""
Core package for SecuriScan.

This package provides the core functionality for the SecuriScan framework.
"""

from securiscan.core.config import AuthConfig, AuthType, ProxyConfig, ScanConfig, ScanLevel
from securiscan.core.exceptions import (
    AuthenticationError,
    BrowserError,
    ConfigurationError,
    ConnectionError,
    ModuleError,
    MonitorError,
    NotificationError,
    ParsingError,
    RateLimitError,
    ReportingError,
    ScanError,
    SecuriScanError,
    TimeoutError,
    ValidationError,
)
from securiscan.core.monitor import Monitor, MonitorConfig, NotificationConfig
from securiscan.core.result import (
    Confidence,
    Evidence,
    ScanResult,
    ScanStatistics,
    ScanTarget,
    Severity,
    TechnologyInfo,
    Vulnerability,
    VulnerabilityType,
)
from securiscan.core.scanner import BaseScanner, Scanner

__all__ = [
    # Configuration
    "ScanConfig",
    "ScanLevel",
    "AuthConfig",
    "AuthType",
    "ProxyConfig",
    
    # Exceptions
    "SecuriScanError",
    "ConfigurationError",
    "ConnectionError",
    "ScanError",
    "ValidationError",
    "AuthenticationError",
    "RateLimitError",
    "TimeoutError",
    "ParsingError",
    "ModuleError",
    "BrowserError",
    "MonitorError",
    "NotificationError",
    "ReportingError",
    
    # Monitor
    "Monitor",
    "MonitorConfig",
    "NotificationConfig",
    
    # Result
    "ScanResult",
    "ScanTarget",
    "ScanStatistics",
    "Vulnerability",
    "Evidence",
    "Severity",
    "Confidence",
    "VulnerabilityType",
    "TechnologyInfo",
    
    # Scanner
    "Scanner",
    "BaseScanner",
]
