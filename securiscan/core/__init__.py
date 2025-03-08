"""
Core modules for SecuriScan.

This package provides core modules for the SecuriScan framework.
"""

from securiscan.core.config import (
    AuthConfig,
    AuthType,
    ProxyConfig,
    ProxyType,
    ScanConfig,
    ScanLevel,
)
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
    "ProxyType",
    "MonitorConfig",
    "NotificationConfig",
    
    # Scanner
    "Scanner",
    "BaseScanner",
    
    # Monitor
    "Monitor",
    
    # Results
    "ScanResult",
    "ScanTarget",
    "ScanStatistics",
    "Vulnerability",
    "Evidence",
    "Severity",
    "Confidence",
    "VulnerabilityType",
    "TechnologyInfo",
    
    # Exceptions
    "SecuriScanError",
    "ConfigurationError",
    "ConnectionError",
    "ScanError",
    "ReportingError",
    "ValidationError",
    "AuthenticationError",
    "RateLimitError",
    "TimeoutError",
    "ParsingError",
    "ModuleError",
    "BrowserError",
    "MonitorError",
    "NotificationError",
]
