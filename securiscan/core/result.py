"""
Result module for SecuriScan.

This module defines the data structures for scan results.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field, HttpUrl, validator


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

    # OWASP Top 10 2021
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    CRYPTOGRAPHIC_FAILURES = "cryptographic_failures"
    INJECTION = "injection"
    INSECURE_DESIGN = "insecure_design"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    AUTH_FAILURES = "authentication_failures"
    SOFTWARE_DATA_INTEGRITY_FAILURES = "software_data_integrity_failures"
    SECURITY_LOGGING_MONITORING_FAILURES = "security_logging_monitoring_failures"
    SSRF = "ssrf"

    # Additional types
    XSS = "xss"
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

    type: str = Field(..., description="Type of evidence (e.g., request, response, screenshot)")
    data: Any = Field(..., description="Evidence data")
    description: Optional[str] = Field(default=None, description="Description of the evidence")
    timestamp: datetime = Field(default_factory=datetime.now, description="Timestamp of evidence")

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class Vulnerability(BaseModel):
    """Vulnerability finding."""

    id: str = Field(..., description="Unique identifier for the vulnerability")
    name: str = Field(..., description="Name of the vulnerability")
    type: VulnerabilityType = Field(..., description="Type of vulnerability")
    severity: Severity = Field(..., description="Severity level")
    confidence: Confidence = Field(..., description="Confidence level")
    description: str = Field(..., description="Description of the vulnerability")
    url: HttpUrl = Field(..., description="URL where the vulnerability was found")
    path: str = Field(..., description="Path component of the URL")
    parameter: Optional[str] = Field(default=None, description="Affected parameter")
    evidence: List[Evidence] = Field(default_factory=list, description="Evidence")
    remediation: str = Field(..., description="Remediation advice")
    references: List[str] = Field(default_factory=list, description="References for more information")
    cwe: Optional[int] = Field(default=None, description="CWE identifier")
    cvss_score: Optional[float] = Field(default=None, description="CVSS score", ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(default=None, description="CVSS vector string")
    tags: Set[str] = Field(default_factory=set, description="Tags for categorization")
    discovered_at: datetime = Field(default_factory=datetime.now, description="Discovery timestamp")
    verified: bool = Field(default=False, description="Whether the vulnerability has been verified")
    false_positive: bool = Field(default=False, description="Whether this is a false positive")
    notes: Optional[str] = Field(default=None, description="Additional notes")

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class ScanStatistics(BaseModel):
    """Statistics about the scan."""

    start_time: datetime = Field(..., description="Scan start time")
    end_time: Optional[datetime] = Field(default=None, description="Scan end time")
    duration_seconds: Optional[float] = Field(default=None, description="Scan duration in seconds")
    urls_discovered: int = Field(default=0, description="Number of URLs discovered")
    urls_scanned: int = Field(default=0, description="Number of URLs scanned")
    requests_sent: int = Field(default=0, description="Number of requests sent")
    vulnerabilities_found: int = Field(default=0, description="Number of vulnerabilities found")
    modules_run: List[str] = Field(default_factory=list, description="Modules that were run")
    scan_level: str = Field(..., description="Scan level used")

    @validator("duration_seconds", always=True)
    def calculate_duration(cls, v, values):
        """Calculate duration if start_time and end_time are available."""
        if values.get("start_time") and values.get("end_time"):
            return (values["end_time"] - values["start_time"]).total_seconds()
        return v


class TechnologyInfo(BaseModel):
    """Information about detected technologies."""

    server: Optional[str] = Field(default=None, description="Server software")
    cms: Optional[str] = Field(default=None, description="Content Management System")
    programming_languages: List[str] = Field(
        default_factory=list, description="Programming languages"
    )
    frameworks: List[str] = Field(default_factory=list, description="Web frameworks")
    javascript_libraries: List[str] = Field(
        default_factory=list, description="JavaScript libraries"
    )
    analytics: List[str] = Field(default_factory=list, description="Analytics services")
    third_party_services: List[str] = Field(
        default_factory=list, description="Third-party services"
    )
    cdn: Optional[str] = Field(default=None, description="Content Delivery Network")
    waf: Optional[str] = Field(default=None, description="Web Application Firewall")
    operating_system: Optional[str] = Field(default=None, description="Operating System")
    database: Optional[str] = Field(default=None, description="Database")


class ScanTarget(BaseModel):
    """Information about the scan target."""

    url: HttpUrl = Field(..., description="Target URL")
    ip: Optional[str] = Field(default=None, description="IP address")
    hostname: str = Field(..., description="Hostname")
    port: int = Field(..., description="Port")
    scheme: str = Field(..., description="Scheme (http/https)")
    technologies: TechnologyInfo = Field(
        default_factory=TechnologyInfo, description="Detected technologies"
    )


class ScanResult(BaseModel):
    """Scan result."""

    id: str = Field(..., description="Unique identifier for the scan")
    target: ScanTarget = Field(..., description="Scan target information")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Discovered vulnerabilities"
    )
    statistics: ScanStatistics = Field(..., description="Scan statistics")
    risk_score: Optional[float] = Field(
        default=None, description="Overall risk score (0-100)", ge=0.0, le=100.0
    )
    risk_level: Optional[str] = Field(
        default=None, description="Risk level (Low, Medium, High, Critical)"
    )
    scan_config: Dict[str, Any] = Field(..., description="Configuration used for the scan")
    created_at: datetime = Field(default_factory=datetime.now, description="Result creation time")
    version: str = Field(..., description="SecuriScan version")

    class Config:
        """Pydantic config."""

        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }

    def to_json(self, pretty: bool = False) -> str:
        """Convert to JSON string.

        Args:
            pretty: Whether to format the JSON with indentation

        Returns:
            JSON string representation of the scan result
        """
        return json.dumps(
            self.dict(),
            indent=4 if pretty else None,
            default=lambda o: o.isoformat() if isinstance(o, datetime) else str(o),
        )

    def get_vulnerabilities_by_severity(self, severity: Severity) -> List[Vulnerability]:
        """Get vulnerabilities by severity.

        Args:
            severity: Severity level to filter by

        Returns:
            List of vulnerabilities with the specified severity
        """
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerabilities_by_type(self, vuln_type: VulnerabilityType) -> List[Vulnerability]:
        """Get vulnerabilities by type.

        Args:
            vuln_type: Vulnerability type to filter by

        Returns:
            List of vulnerabilities of the specified type
        """
        return [v for v in self.vulnerabilities if v.type == vuln_type]

    def calculate_risk_score(self) -> float:
        """Calculate the overall risk score based on vulnerabilities.

        Returns:
            Risk score between 0 and 100
        """
        if not self.vulnerabilities:
            return 0.0

        # Severity weights
        weights = {
            Severity.INFO: 0.1,
            Severity.LOW: 1.0,
            Severity.MEDIUM: 4.0,
            Severity.HIGH: 9.0,
            Severity.CRITICAL: 16.0,
        }

        # Calculate weighted score
        total_weight = sum(weights.values())
        max_score = total_weight * 100

        score = 0.0
        for vuln in self.vulnerabilities:
            score += weights[vuln.severity]

        # Normalize to 0-100 scale
        normalized_score = (score / max_score) * 100
        return min(100.0, normalized_score)

    def determine_risk_level(self) -> str:
        """Determine the risk level based on the risk score.

        Returns:
            Risk level as a string
        """
        score = self.risk_score or self.calculate_risk_score()

        if score >= 75:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 25:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "None"

    def update_risk_assessment(self) -> None:
        """Update the risk score and level."""
        self.risk_score = self.calculate_risk_score()
        self.risk_level = self.determine_risk_level()

    def generate_report(self, output_path: str, format: str = "html") -> str:
        """Generate a report of the scan results.

        Args:
            output_path: Path to save the report
            format: Report format (html, pdf, json, csv)

        Returns:
            Path to the generated report

        Raises:
            ValueError: If the format is not supported
        """
        from securiscan.reporting.generator import ReportGenerator

        generator = ReportGenerator(self)
        return generator.generate(output_path, format)
