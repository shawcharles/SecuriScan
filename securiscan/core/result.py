"""
Result module for SecuriScan.

This module defines the data structures for scan results.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Vulnerability severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence levels for vulnerability findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities."""

    XSS = "xss"
    SQL_INJECTION = "sql_injection"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    INFORMATION_DISCLOSURE = "information_disclosure"
    INSECURE_HEADERS = "insecure_headers"
    SSL_TLS_ISSUES = "ssl_tls_issues"
    INSECURE_COOKIE = "insecure_cookie"
    DIRECTORY_LISTING = "directory_listing"
    FILE_INCLUSION = "file_inclusion"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    CLICKJACKING = "clickjacking"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    XML_EXTERNAL_ENTITY = "xxe"
    BUSINESS_LOGIC = "business_logic"
    API_SECURITY = "api_security"
    RATE_LIMITING = "rate_limiting"
    BRUTE_FORCE = "brute_force"
    WEAK_PASSWORD = "weak_password"
    OUTDATED_COMPONENT = "outdated_component"
    MISCONFIGURATION = "misconfiguration"
    OTHER = "other"


class Evidence(BaseModel):
    """Evidence for a vulnerability."""

    type: str
    data: Any
    description: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class Vulnerability(BaseModel):
    """Vulnerability finding."""

    id: str
    name: str
    type: VulnerabilityType
    severity: Severity
    confidence: Confidence
    description: str
    url: str
    path: str
    parameter: Optional[str] = None
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: str
    references: List[str] = Field(default_factory=list)
    cwe: Optional[int] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    tags: Set[str] = Field(default_factory=set)
    discovered_at: datetime = Field(default_factory=datetime.now)
    verified: bool = False
    false_positive: bool = False
    notes: Optional[str] = None


class ScanStatistics(BaseModel):
    """Statistics about the scan."""

    start_time: datetime
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    pages_scanned: int = 0
    requests_sent: int = 0
    vulnerabilities_found: int = 0
    scan_level: str

    @property
    def duration_seconds(self) -> Optional[float]:
        """Get the scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return self.duration


class TechnologyInfo(BaseModel):
    """Information about detected technologies."""

    version: Optional[str] = None
    server: Optional[str] = None
    cms: Optional[str] = None
    programming_languages: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    javascript_libraries: List[str] = Field(default_factory=list)
    analytics: List[str] = Field(default_factory=list)
    third_party_services: List[str] = Field(default_factory=list)
    cdn: Optional[str] = None
    waf: Optional[str] = None
    operating_system: Optional[str] = None
    database: Optional[str] = None

class ScanTarget(BaseModel):
    """Information about the scan target."""

    url: str
    ip: Optional[str] = None
    hostname: str
    port: int
    scheme: str
    technologies: TechnologyInfo = Field(default_factory=TechnologyInfo)


class ScanResult(BaseModel):
    """Scan result."""

    id: str
    target: ScanTarget
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    statistics: ScanStatistics
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    scan_config: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.now)
    version: str

    @property
    def duration(self) -> float:
        """Get the scan duration in seconds."""
        return self.statistics.duration_seconds or 0.0

    def generate_report(self, output_path: str, format: str = "html") -> str:
        """Generate a report of the scan results.

        Args:
            output_path: Path to save the report
            format: Report format (html, pdf, json, csv)

        Returns:
            Path to the generated report
        """
        # Simple implementation for the example
        with open(output_path, "w") as f:
            if format == "html":
                f.write("<html><body><h1>Scan Report</h1></body></html>")
            elif format == "json":
                json.dump(self.dict(), f, default=str, indent=2)
            else:
                f.write(str(self.dict()))
        
        return output_path
