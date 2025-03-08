"""
SecuriScan: Professional Web Security Testing Framework.

This package provides a comprehensive framework for security testing of web applications.
"""

__version__ = "0.1.0"

# Import core components
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

# Define public API
__all__ = [
    # Version
    "__version__",
    
    # Core components
    "Scanner",
    "BaseScanner",
    "Monitor",
    
    # Configuration
    "ScanConfig",
    "ScanLevel",
    "AuthConfig",
    "AuthType",
    "ProxyConfig",
    "ProxyType",
    "MonitorConfig",
    "NotificationConfig",
    
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
