"""
Utilities package for SecuriScan.

This package provides utility functions for the SecuriScan framework.
"""

from securiscan.utils.http import (
    extract_form_data,
    extract_urls_from_html,
    extract_urls_from_js,
    get_base_url,
    get_domain,
    get_ssl_info,
    is_same_domain,
    is_subdomain,
    normalize_url,
    parse_cookies,
    parse_query_string,
)
from securiscan.utils.validation import (
    is_valid_cidr,
    is_valid_domain,
    is_valid_email,
    is_valid_file_path,
    is_valid_hostname,
    is_valid_http_header_name,
    is_valid_http_method,
    is_valid_http_status_code,
    is_valid_ip,
    is_valid_ip_range,
    is_valid_mac_address,
    is_valid_port,
    is_valid_url,
    is_valid_uuid,
)

__all__ = [
    # HTTP utilities
    "extract_form_data",
    "extract_urls_from_html",
    "extract_urls_from_js",
    "get_base_url",
    "get_domain",
    "get_ssl_info",
    "is_same_domain",
    "is_subdomain",
    "normalize_url",
    "parse_cookies",
    "parse_query_string",
    
    # Validation utilities
    "is_valid_cidr",
    "is_valid_domain",
    "is_valid_email",
    "is_valid_file_path",
    "is_valid_hostname",
    "is_valid_http_header_name",
    "is_valid_http_method",
    "is_valid_http_status_code",
    "is_valid_ip",
    "is_valid_ip_range",
    "is_valid_mac_address",
    "is_valid_port",
    "is_valid_url",
    "is_valid_uuid",
]
