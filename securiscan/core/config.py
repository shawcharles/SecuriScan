"""
Configuration module for SecuriScan.

This module defines the configuration options for the SecuriScan framework.
"""

from enum import Enum
from typing import Dict, List, Optional, Set, Union

from pydantic import BaseModel, Field, HttpUrl, validator


class ScanLevel(str, Enum):
    """Scan level enum."""

    PASSIVE = "passive"
    LIGHT = "light"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class AuthType(str, Enum):
    """Authentication type enum."""

    NONE = "none"
    BASIC = "basic"
    DIGEST = "digest"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    CUSTOM = "custom"


class ProxyType(str, Enum):
    """Proxy type enum."""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyConfig(BaseModel):
    """Proxy configuration."""

    type: ProxyType = Field(default=ProxyType.HTTP, description="Proxy type")
    host: str = Field(..., description="Proxy host")
    port: int = Field(..., description="Proxy port")
    username: Optional[str] = Field(default=None, description="Proxy username")
    password: Optional[str] = Field(default=None, description="Proxy password")

    class Config:
        """Pydantic config."""

        extra = "forbid"


class AuthConfig(BaseModel):
    """Authentication configuration."""

    type: AuthType = Field(default=AuthType.NONE, description="Authentication type")
    username: Optional[str] = Field(default=None, description="Username for basic/digest auth")
    password: Optional[str] = Field(default=None, description="Password for basic/digest auth")
    token: Optional[str] = Field(default=None, description="Token for bearer auth")
    oauth_client_id: Optional[str] = Field(default=None, description="OAuth2 client ID")
    oauth_client_secret: Optional[str] = Field(default=None, description="OAuth2 client secret")
    oauth_token_url: Optional[HttpUrl] = Field(default=None, description="OAuth2 token URL")
    oauth_scopes: Optional[List[str]] = Field(default=None, description="OAuth2 scopes")
    custom_auth_header: Optional[str] = Field(
        default=None, description="Custom auth header name"
    )
    custom_auth_value: Optional[str] = Field(
        default=None, description="Custom auth header value"
    )

    class Config:
        """Pydantic config."""

        extra = "forbid"

    @validator("username")
    def username_required_for_basic_digest(cls, v, values):
        """Validate that username is provided for basic/digest auth."""
        if values.get("type") in [AuthType.BASIC, AuthType.DIGEST] and not v:
            raise ValueError("Username is required for basic/digest authentication")
        return v

    @validator("password")
    def password_required_for_basic_digest(cls, v, values):
        """Validate that password is provided for basic/digest auth."""
        if values.get("type") in [AuthType.BASIC, AuthType.DIGEST] and not v:
            raise ValueError("Password is required for basic/digest authentication")
        return v

    @validator("token")
    def token_required_for_bearer(cls, v, values):
        """Validate that token is provided for bearer auth."""
        if values.get("type") == AuthType.BEARER and not v:
            raise ValueError("Token is required for bearer authentication")
        return v

    @validator("custom_auth_header", "custom_auth_value")
    def custom_auth_required_fields(cls, v, values):
        """Validate that custom auth fields are provided for custom auth."""
        if values.get("type") == AuthType.CUSTOM and not v:
            raise ValueError(
                "Custom auth header and value are required for custom authentication"
            )
        return v


class ScanConfig(BaseModel):
    """Scan configuration."""

    # General settings
    scan_level: ScanLevel = Field(
        default=ScanLevel.STANDARD, description="Scan intensity level"
    )
    max_depth: int = Field(default=3, description="Maximum crawl depth", ge=1, le=10)
    max_urls: int = Field(
        default=1000, description="Maximum number of URLs to scan", ge=1, le=10000
    )
    threads: int = Field(default=10, description="Number of threads to use", ge=1, le=50)
    timeout: int = Field(default=30, description="Request timeout in seconds", ge=1, le=300)
    delay: float = Field(
        default=0.0, description="Delay between requests in seconds", ge=0.0, le=10.0
    )
    user_agent: str = Field(
        default="SecuriScan/0.1.0 (+https://github.com/yourusername/securiscan)",
        description="User agent string",
    )
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")
    follow_redirects: bool = Field(default=True, description="Follow redirects")
    max_redirects: int = Field(default=10, description="Maximum number of redirects", ge=0, le=20)

    # Authentication
    auth: Optional[AuthConfig] = Field(default=None, description="Authentication configuration")

    # Proxy
    proxy: Optional[ProxyConfig] = Field(default=None, description="Proxy configuration")

    # Headers and cookies
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Custom cookies")

    # Scope
    include_subdomains: bool = Field(
        default=False, description="Include subdomains in the scan"
    )
    allowed_hosts: Set[str] = Field(
        default_factory=set, description="Additional hosts to include in the scan"
    )
    excluded_paths: Set[str] = Field(
        default_factory=set, description="Paths to exclude from the scan"
    )
    excluded_extensions: Set[str] = Field(
        default_factory=lambda: {"css", "js", "jpg", "jpeg", "png", "gif", "svg", "ico"},
        description="File extensions to exclude from the scan",
    )

    # Scanner modules
    enabled_modules: Optional[Set[str]] = Field(
        default=None, description="Specific modules to enable (None = all)"
    )
    disabled_modules: Set[str] = Field(
        default_factory=set, description="Specific modules to disable"
    )

    # Browser automation
    use_browser: bool = Field(
        default=False, description="Use headless browser for client-side testing"
    )
    browser_type: str = Field(
        default="chromium", description="Browser type (chromium, firefox, webkit)"
    )
    browser_args: List[str] = Field(
        default_factory=list, description="Additional browser arguments"
    )

    # Rate limiting
    smart_rate_limiting: bool = Field(
        default=True, description="Enable smart rate limiting"
    )
    max_requests_per_second: float = Field(
        default=10.0, description="Maximum requests per second", ge=0.1
    )

    # Reporting
    evidence_collection: bool = Field(
        default=True, description="Collect evidence for vulnerabilities"
    )
    screenshot_evidence: bool = Field(
        default=True, description="Take screenshots as evidence (requires browser)"
    )

    class Config:
        """Pydantic config."""

        extra = "forbid"

    @validator("headers")
    def no_auth_in_headers(cls, v, values):
        """Validate that authentication is not in headers."""
        auth_headers = ["authorization", "proxy-authorization"]
        for header in v.keys():
            if header.lower() in auth_headers:
                raise ValueError(
                    f"Authentication should be configured using the auth field, not in headers: {header}"
                )
        return v

    @validator("screenshot_evidence")
    def screenshot_requires_browser(cls, v, values):
        """Validate that screenshot evidence requires browser."""
        if v and not values.get("use_browser", False):
            raise ValueError("Screenshot evidence requires use_browser to be enabled")
        return v

    @classmethod
    def passive(cls, **kwargs) -> "ScanConfig":
        """Create a passive scan configuration."""
        return cls(scan_level=ScanLevel.PASSIVE, **kwargs)

    @classmethod
    def light(cls, **kwargs) -> "ScanConfig":
        """Create a light scan configuration."""
        return cls(scan_level=ScanLevel.LIGHT, **kwargs)

    @classmethod
    def standard(cls, **kwargs) -> "ScanConfig":
        """Create a standard scan configuration."""
        return cls(scan_level=ScanLevel.STANDARD, **kwargs)

    @classmethod
    def aggressive(cls, **kwargs) -> "ScanConfig":
        """Create an aggressive scan configuration."""
        return cls(scan_level=ScanLevel.AGGRESSIVE, **kwargs)
