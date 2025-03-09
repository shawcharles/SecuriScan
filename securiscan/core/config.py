from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, HttpUrl, validator

class ScanLevel(Enum):
    LIGHT = 'light'
    PASSIVE = 'passive'
    STANDARD = 'standard'
    DEEP = 'deep'
    FULL = 'full'

class AuthType(Enum):
    """Authentication type."""
    BASIC = 'basic'
    BEARER_TOKEN = 'bearer_token'
    API_KEY = 'api_key'

class AuthConfig(BaseModel):
    """Authentication configuration."""
    auth_type: AuthType
    credentials: Dict[str, str]

    def model_dump(self, **kwargs):
        data = super().model_dump(**kwargs)
        data['auth_type'] = self.auth_type.value
        return data

class ProxyConfig(BaseModel):
    """Proxy configuration."""
    proxy_url: HttpUrl
    proxy_auth: Optional[Dict[str, str]] = None

    def model_dump(self, **kwargs):
        data = super().model_dump(**kwargs)
        data['proxy_url'] = str(self.proxy_url)
        return data

class NotificationConfig(BaseModel):
    """Notification configuration."""
    enabled: bool = False
    email_recipients: List[str] = Field(default_factory=list)
    sms_recipients: List[str] = Field(default_factory=list)
    webhook_url: Optional[str] = None

class ScanConfig(BaseModel):
    """Scan configuration."""

    scan_level: ScanLevel = ScanLevel.STANDARD
    max_depth: int = 3
    max_urls: int = 1000
    threads: int = 10
    timeout: int = 30
    delay: float = 0.0
    user_agent: Optional[str] = "SecuriScan/0.1.0"
    verify_ssl: bool = True
    follow_redirects: bool = True
    allow_subdomains: bool = False
    max_redirects: int = 10
    smart_rate_limiting: bool = True
    max_requests_per_second: float = 10.0
    enabled_modules: Optional[Set[str]] = None
    disabled_modules: Set[str] = Field(default_factory=set)
    excluded_paths: List[str] = Field(default_factory=list)
    included_paths: List[str] = Field(default_factory=list)
    excluded_extensions: List[str] = Field(default_factory=list)
    included_extensions: List[str] = Field(default_factory=list)
    excluded_parameters: List[str] = Field(default_factory=list)
    rate_limit: int = 0
    custom_settings: Dict[str, Union[str, int, float, bool, List[str], Dict[str, str]]] = Field(default_factory=dict)
    auth_config: Optional[AuthConfig] = None
    proxy_config: Optional[ProxyConfig] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    notification_config: Optional[NotificationConfig] = None
