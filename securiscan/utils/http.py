"""
HTTP Utility Module.

This module provides utility functions for HTTP operations.
"""

import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from requests.cookies import RequestsCookieJar


def normalize_url(url: str) -> str:
    """Normalize a URL by removing fragments and normalizing the path.

    Args:
        url: URL to normalize

    Returns:
        Normalized URL
    """
    parsed = urlparse(url)
    
    # Ensure scheme is present
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)
    
    # Remove fragments
    url = parsed._replace(fragment="").geturl()
    
    # Normalize path (remove duplicate slashes, etc.)
    path_parts = parsed.path.split("/")
    normalized_parts = []
    
    for part in path_parts:
        if part == "..":
            if normalized_parts:
                normalized_parts.pop()
        elif part and part != ".":
            normalized_parts.append(part)
    
    normalized_path = "/" + "/".join(normalized_parts)
    
    # Reconstruct URL
    parsed = parsed._replace(path=normalized_path)
    return parsed.geturl()


def get_base_url(url: str) -> str:
    """Get the base URL (scheme + netloc) from a URL.

    Args:
        url: URL to get base URL from

    Returns:
        Base URL
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def get_domain(url: str) -> str:
    """Get the domain from a URL.

    Args:
        url: URL to get domain from

    Returns:
        Domain
    """
    parsed = urlparse(url)
    return parsed.netloc


def is_same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs have the same domain.

    Args:
        url1: First URL
        url2: Second URL

    Returns:
        True if the URLs have the same domain, False otherwise
    """
    domain1 = get_domain(url1)
    domain2 = get_domain(url2)
    return domain1 == domain2


def is_subdomain(domain: str, parent_domain: str) -> bool:
    """Check if a domain is a subdomain of another domain.

    Args:
        domain: Domain to check
        parent_domain: Parent domain to check against

    Returns:
        True if the domain is a subdomain of the parent domain, False otherwise
    """
    # Remove port if present
    domain = domain.split(":")[0]
    parent_domain = parent_domain.split(":")[0]
    
    # Check if domain ends with parent_domain
    if domain.endswith(parent_domain) and domain != parent_domain:
        # Check if the character before parent_domain is a dot
        prefix_len = len(domain) - len(parent_domain)
        return prefix_len > 0 and domain[prefix_len - 1] == "."
    
    return False


def extract_urls_from_html(html: str, base_url: str) -> List[str]:
    """Extract URLs from HTML content.

    Args:
        html: HTML content
        base_url: Base URL for resolving relative URLs

    Returns:
        List of URLs
    """
    # Simple regex pattern to find URLs in HTML
    # This is a basic implementation and may not catch all URLs
    url_pattern = re.compile(r'(?:href|src)=["\'](.*?)["\']', re.IGNORECASE)
    matches = url_pattern.findall(html)
    
    # Resolve relative URLs and normalize
    urls = []
    for match in matches:
        # Skip empty URLs, anchors, and javascript:
        if not match or match.startswith("#") or match.startswith("javascript:"):
            continue
        
        # Resolve relative URL
        absolute_url = urljoin(base_url, match)
        
        # Normalize URL
        normalized_url = normalize_url(absolute_url)
        
        urls.append(normalized_url)
    
    return urls


def extract_urls_from_js(js: str, base_url: str) -> List[str]:
    """Extract URLs from JavaScript content.

    Args:
        js: JavaScript content
        base_url: Base URL for resolving relative URLs

    Returns:
        List of URLs
    """
    # Regex patterns to find URLs in JavaScript
    patterns = [
        r'(?:url|href|src):\s*["\']([^"\']+)["\']',  # url: "..."
        r'(?:url|href|src)\(["\']([^"\']+)["\']\)',  # url("...")
        r'["\']([^"\']*?(?:\.json|\.php|\.asp|\.aspx|\.jsp|\.do|\.action)[^"\']*?)["\']',  # "...json" or "...php" etc.
    ]
    
    urls = []
    for pattern in patterns:
        matches = re.findall(pattern, js, re.IGNORECASE)
        for match in matches:
            # Skip empty URLs, anchors, and javascript:
            if not match or match.startswith("#") or match.startswith("javascript:"):
                continue
            
            # Resolve relative URL
            absolute_url = urljoin(base_url, match)
            
            # Normalize URL
            normalized_url = normalize_url(absolute_url)
            
            urls.append(normalized_url)
    
    return urls


def extract_form_data(html: str, form_index: int = 0) -> Dict[str, str]:
    """Extract form data from HTML content.

    Args:
        html: HTML content
        form_index: Index of the form to extract (0-based)

    Returns:
        Dictionary of form field names and values
    """
    # Find all forms
    form_pattern = re.compile(r'<form.*?</form>', re.DOTALL | re.IGNORECASE)
    forms = form_pattern.findall(html)
    
    if not forms or form_index >= len(forms):
        return {}
    
    form = forms[form_index]
    
    # Find all input fields
    input_pattern = re.compile(r'<input.*?>', re.IGNORECASE)
    inputs = input_pattern.findall(form)
    
    # Extract field names and values
    form_data = {}
    for input_field in inputs:
        name_match = re.search(r'name=["\'](.*?)["\']', input_field, re.IGNORECASE)
        value_match = re.search(r'value=["\'](.*?)["\']', input_field, re.IGNORECASE)
        
        if name_match:
            name = name_match.group(1)
            value = value_match.group(1) if value_match else ""
            form_data[name] = value
    
    return form_data


def get_ssl_info(hostname: str, port: int = 443) -> Dict[str, any]:
    """Get SSL/TLS information for a hostname.

    Args:
        hostname: Hostname to check
        port: Port to connect to

    Returns:
        Dictionary of SSL/TLS information
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert = ssock.getpeercert()
                
                # Get cipher
                cipher = ssock.cipher()
                
                # Get protocol version
                protocol = ssock.version()
                
                return {
                    "certificate": cert,
                    "cipher": {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2],
                    },
                    "protocol": protocol,
                }
    except Exception as e:
        return {"error": str(e)}


def parse_cookies(cookie_string: str) -> Dict[str, str]:
    """Parse a cookie string into a dictionary.

    Args:
        cookie_string: Cookie string (e.g., "name1=value1; name2=value2")

    Returns:
        Dictionary of cookie names and values
    """
    cookies = {}
    
    if not cookie_string:
        return cookies
    
    for cookie in cookie_string.split(";"):
        cookie = cookie.strip()
        if not cookie:
            continue
        
        parts = cookie.split("=", 1)
        if len(parts) == 2:
            name, value = parts
            cookies[name.strip()] = value.strip()
    
    return cookies


def parse_query_string(query_string: str) -> Dict[str, List[str]]:
    """Parse a query string into a dictionary.

    Args:
        query_string: Query string (e.g., "name1=value1&name2=value2")

    Returns:
        Dictionary of parameter names and values
    """
    return parse_qs(query_string)


def create_user_agent(browser: str = "chrome", os: str = "windows") -> str:
    """Create a user agent string.

    Args:
        browser: Browser name (chrome, firefox, safari, edge)
        os: Operating system (windows, macos, linux, android, ios)

    Returns:
        User agent string
    """
    user_agents = {
        "chrome": {
            "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "linux": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "android": "Mozilla/5.0 (Linux; Android 10; SM-A205U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
            "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/91.0.4472.80 Mobile/15E148 Safari/604.1",
        },
        "firefox": {
            "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
            "linux": "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "android": "Mozilla/5.0 (Android 10; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
            "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/34.0 Mobile/15E148 Safari/605.1.15",
        },
        "safari": {
            "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        },
        "edge": {
            "windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "macos": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        },
    }
    
    browser = browser.lower()
    os = os.lower()
    
    if browser in user_agents and os in user_agents[browser]:
        return user_agents[browser][os]
    
    # Default to Chrome on Windows
    return user_agents["chrome"]["windows"]


def detect_waf(response: requests.Response) -> Optional[str]:
    """Detect if a response is from a Web Application Firewall (WAF).

    Args:
        response: HTTP response

    Returns:
        WAF name if detected, None otherwise
    """
    # Check for common WAF signatures in headers
    headers = response.headers
    
    # Cloudflare
    if "cf-ray" in headers or "cloudflare" in headers.get("server", "").lower():
        return "Cloudflare"
    
    # Akamai
    if "akamai" in headers.get("server", "").lower() or "akamaighost" in headers.get("server", "").lower():
        return "Akamai"
    
    # Imperva/Incapsula
    if "incap" in headers or "incapsula" in headers:
        return "Imperva/Incapsula"
    
    # F5 BIG-IP ASM
    if "bigip" in headers or "f5" in headers.get("server", "").lower():
        return "F5 BIG-IP ASM"
    
    # AWS WAF
    if "awselb" in headers or "aws" in headers.get("server", "").lower():
        return "AWS WAF"
    
    # Sucuri
    if "sucuri" in headers:
        return "Sucuri"
    
    # ModSecurity
    if "mod_security" in headers or "modsecurity" in headers:
        return "ModSecurity"
    
    # Check for common WAF signatures in content
    content = response.text.lower()
    
    # Cloudflare
    if "cloudflare" in content and ("ray id" in content or "security check" in content):
        return "Cloudflare"
    
    # Akamai
    if "akamai" in content and "reference number" in content:
        return "Akamai"
    
    # Imperva/Incapsula
    if "incapsula" in content or "imperva" in content:
        return "Imperva/Incapsula"
    
    # Sucuri
    if "sucuri" in content and "security" in content:
        return "Sucuri"
    
    return None


def is_rate_limited(response: requests.Response) -> Tuple[bool, Optional[int]]:
    """Check if a response indicates rate limiting.

    Args:
        response: HTTP response

    Returns:
        Tuple of (is_rate_limited, retry_after)
    """
    # Check status code
    if response.status_code in [429, 503]:
        # Check for Retry-After header
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                return True, int(retry_after)
            except ValueError:
                # Retry-After could be a date string
                return True, None
        return True, None
    
    # Check for rate limiting in headers
    headers = response.headers
    rate_limit_headers = [
        "x-rate-limit-remaining",
        "x-ratelimit-remaining",
        "ratelimit-remaining",
    ]
    
    for header in rate_limit_headers:
        if header in headers:
            try:
                remaining = int(headers[header])
                if remaining <= 0:
                    return True, None
            except ValueError:
                pass
    
    # Check for rate limiting in content
    content = response.text.lower()
    rate_limit_phrases = [
        "rate limit",
        "rate limited",
        "too many requests",
        "throttled",
        "exceeded",
    ]
    
    for phrase in rate_limit_phrases:
        if phrase in content:
            return True, None
    
    return False, None
