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
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class AuthType(str, Enum):
    """Authentication type enum."""

    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"
    FORM = "form"


class AuthConfig(BaseModel):
    """Authentication configuration."""

    username: str
    password: str
    auth_type: AuthType = AuthType.BASIC


class ProxyConfig(BaseModel):
    """Proxy configuration."""

    url: str


class ScanConfig(BaseModel):
    """Scan configuration."""

    scan_level: ScanLevel = ScanLevel.STANDARD
    max_depth: int = 3
    threads: int = 10
    timeout: int = 30
    auth_config: Optional[AuthConfig] = None
    proxy_config: Optional[ProxyConfig] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    user_agent: str = "SecuriScan/0.1.0"
    verify_ssl: bool = True
    follow_redirects: bool = True
    max_redirects: int = 10
    smart_rate_limiting: bool = True
    max_requests_per_second: float = 10.0
    enabled_modules: Optional[Set[str]] = None
    disabled_modules: Set[str] = Field(default_factory=set)
