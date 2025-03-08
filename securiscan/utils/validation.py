"""
Validation Utility Module.

This module provides utility functions for input validation.
"""

import ipaddress
import re
import socket
from typing import List, Optional, Union
from urllib.parse import urlparse


def is_valid_url(url: str) -> bool:
    """Check if a URL is valid.

    Args:
        url: URL to check

    Returns:
        True if the URL is valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if an IP address is valid.

    Args:
        ip: IP address to check

    Returns:
        True if the IP address is valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if a domain name is valid.

    Args:
        domain: Domain name to check

    Returns:
        True if the domain name is valid, False otherwise
    """
    # Remove port if present
    domain = domain.split(":")[0]
    
    # Check domain format
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    
    return bool(domain_pattern.match(domain))


def is_valid_email(email: str) -> bool:
    """Check if an email address is valid.

    Args:
        email: Email address to check

    Returns:
        True if the email address is valid, False otherwise
    """
    email_pattern = re.compile(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    )
    
    return bool(email_pattern.match(email))


def is_valid_port(port: Union[str, int]) -> bool:
    """Check if a port number is valid.

    Args:
        port: Port number to check

    Returns:
        True if the port number is valid, False otherwise
    """
    try:
        port_num = int(port)
        return 0 < port_num < 65536
    except (ValueError, TypeError):
        return False


def is_valid_ip_range(ip_range: str) -> bool:
    """Check if an IP range is valid.

    Args:
        ip_range: IP range to check (e.g., "192.168.1.0/24")

    Returns:
        True if the IP range is valid, False otherwise
    """
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        return False


def is_valid_mac_address(mac: str) -> bool:
    """Check if a MAC address is valid.

    Args:
        mac: MAC address to check

    Returns:
        True if the MAC address is valid, False otherwise
    """
    mac_pattern = re.compile(
        r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    )
    
    return bool(mac_pattern.match(mac))


def is_valid_hostname(hostname: str) -> bool:
    """Check if a hostname is valid.

    Args:
        hostname: Hostname to check

    Returns:
        True if the hostname is valid, False otherwise
    """
    # Remove port if present
    hostname = hostname.split(":")[0]
    
    # Check hostname format
    hostname_pattern = re.compile(
        r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )
    
    # Check each part of the hostname
    parts = hostname.split(".")
    
    if len(parts) > 1:
        return all(hostname_pattern.match(part) for part in parts) and is_valid_domain(hostname)
    else:
        return bool(hostname_pattern.match(hostname))


def is_valid_uuid(uuid: str) -> bool:
    """Check if a UUID is valid.

    Args:
        uuid: UUID to check

    Returns:
        True if the UUID is valid, False otherwise
    """
    uuid_pattern = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE
    )
    
    return bool(uuid_pattern.match(uuid))


def is_valid_cidr(cidr: str) -> bool:
    """Check if a CIDR notation is valid.

    Args:
        cidr: CIDR notation to check (e.g., "192.168.1.0/24")

    Returns:
        True if the CIDR notation is valid, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_http_method(method: str) -> bool:
    """Check if an HTTP method is valid.

    Args:
        method: HTTP method to check

    Returns:
        True if the HTTP method is valid, False otherwise
    """
    valid_methods = [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"
    ]
    
    return method.upper() in valid_methods


def is_valid_http_header_name(header_name: str) -> bool:
    """Check if an HTTP header name is valid.

    Args:
        header_name: HTTP header name to check

    Returns:
        True if the HTTP header name is valid, False otherwise
    """
    header_pattern = re.compile(r"^[a-zA-Z0-9-]+$")
    
    return bool(header_pattern.match(header_name))


def is_valid_http_status_code(status_code: Union[str, int]) -> bool:
    """Check if an HTTP status code is valid.

    Args:
        status_code: HTTP status code to check

    Returns:
        True if the HTTP status code is valid, False otherwise
    """
    try:
        code = int(status_code)
        return 100 <= code < 600
    except (ValueError, TypeError):
        return False


def is_valid_file_path(path: str) -> bool:
    """Check if a file path is valid.

    Args:
        path: File path to check

    Returns:
        True if the file path is valid, False otherwise
    """
    # This is a basic check and may not catch all invalid paths
    # For a more thorough check, consider using os.path functions
    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    
    return not any(char in path for char in invalid_chars)


def is_valid_directory_path(path: str) -> bool:
    """Check if a directory path is valid.

    Args:
        path: Directory path to check

    Returns:
        True if the directory path is valid, False otherwise
    """
    # This is a basic check and may not catch all invalid paths
    # For a more thorough check, consider using os.path functions
    invalid_chars = ['<', '>', ':', '"', '|', '?', '*']
    
    return not any(char in path for char in invalid_chars)


def is_valid_json_string(json_str: str) -> bool:
    """Check if a string is valid JSON.

    Args:
        json_str: JSON string to check

    Returns:
        True if the string is valid JSON, False otherwise
    """
    try:
        import json
        json.loads(json_str)
        return True
    except (ValueError, TypeError):
        return False


def is_valid_xml_string(xml_str: str) -> bool:
    """Check if a string is valid XML.

    Args:
        xml_str: XML string to check

    Returns:
        True if the string is valid XML, False otherwise
    """
    try:
        import xml.etree.ElementTree as ET
        ET.fromstring(xml_str)
        return True
    except ET.ParseError:
        return False
    except Exception:
        return False


def is_valid_base64(base64_str: str) -> bool:
    """Check if a string is valid base64.

    Args:
        base64_str: Base64 string to check

    Returns:
        True if the string is valid base64, False otherwise
    """
    import base64
    
    # Check if the string contains only base64 characters
    base64_pattern = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
    
    if not base64_pattern.match(base64_str):
        return False
    
    # Check if the length is valid
    if len(base64_str) % 4 != 0:
        return False
    
    # Try to decode
    try:
        base64.b64decode(base64_str)
        return True
    except Exception:
        return False


def is_valid_hex_string(hex_str: str) -> bool:
    """Check if a string is a valid hexadecimal string.

    Args:
        hex_str: Hexadecimal string to check

    Returns:
        True if the string is a valid hexadecimal string, False otherwise
    """
    hex_pattern = re.compile(r"^[0-9a-fA-F]+$")
    
    return bool(hex_pattern.match(hex_str))


def is_valid_md5(md5_str: str) -> bool:
    """Check if a string is a valid MD5 hash.

    Args:
        md5_str: MD5 hash to check

    Returns:
        True if the string is a valid MD5 hash, False otherwise
    """
    md5_pattern = re.compile(r"^[0-9a-fA-F]{32}$")
    
    return bool(md5_pattern.match(md5_str))


def is_valid_sha1(sha1_str: str) -> bool:
    """Check if a string is a valid SHA-1 hash.

    Args:
        sha1_str: SHA-1 hash to check

    Returns:
        True if the string is a valid SHA-1 hash, False otherwise
    """
    sha1_pattern = re.compile(r"^[0-9a-fA-F]{40}$")
    
    return bool(sha1_pattern.match(sha1_str))


def is_valid_sha256(sha256_str: str) -> bool:
    """Check if a string is a valid SHA-256 hash.

    Args:
        sha256_str: SHA-256 hash to check

    Returns:
        True if the string is a valid SHA-256 hash, False otherwise
    """
    sha256_pattern = re.compile(r"^[0-9a-fA-F]{64}$")
    
    return bool(sha256_pattern.match(sha256_str))


def is_valid_credit_card(card_number: str) -> bool:
    """Check if a credit card number is valid using the Luhn algorithm.

    Args:
        card_number: Credit card number to check

    Returns:
        True if the credit card number is valid, False otherwise
    """
    # Remove spaces and dashes
    card_number = card_number.replace(" ", "").replace("-", "")
    
    # Check if the card number contains only digits
    if not card_number.isdigit():
        return False
    
    # Check length (most card numbers are 13-19 digits)
    if not 13 <= len(card_number) <= 19:
        return False
    
    # Luhn algorithm
    digits = [int(d) for d in card_number]
    checksum = 0
    
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    
    return checksum % 10 == 0


def is_valid_ssn(ssn: str) -> bool:
    """Check if a US Social Security Number (SSN) is valid.

    Args:
        ssn: SSN to check

    Returns:
        True if the SSN is valid, False otherwise
    """
    # Remove dashes
    ssn = ssn.replace("-", "")
    
    # Check if the SSN contains only digits and has the correct length
    if not ssn.isdigit() or len(ssn) != 9:
        return False
    
    # Check if the SSN is not all zeros in any group
    if ssn[:3] == "000" or ssn[3:5] == "00" or ssn[5:] == "0000":
        return False
    
    # Check if the SSN doesn't start with 666 or 9
    if ssn.startswith("666") or ssn.startswith("9"):
        return False
    
    return True


def is_valid_phone_number(phone: str) -> bool:
    """Check if a phone number is valid.

    Args:
        phone: Phone number to check

    Returns:
        True if the phone number is valid, False otherwise
    """
    # Remove common separators
    phone = re.sub(r"[\s\-\(\)\.]", "", phone)
    
    # Check if the phone number contains only digits and optional leading +
    if not (phone.isdigit() or (phone.startswith("+") and phone[1:].isdigit())):
        return False
    
    # Check length (most phone numbers are 7-15 digits)
    if not 7 <= len(phone.replace("+", "")) <= 15:
        return False
    
    return True


def is_valid_date(date_str: str, format: str = "%Y-%m-%d") -> bool:
    """Check if a date string is valid.

    Args:
        date_str: Date string to check
        format: Date format (default: YYYY-MM-DD)

    Returns:
        True if the date string is valid, False otherwise
    """
    from datetime import datetime
    
    try:
        datetime.strptime(date_str, format)
        return True
    except ValueError:
        return False


def is_valid_time(time_str: str, format: str = "%H:%M:%S") -> bool:
    """Check if a time string is valid.

    Args:
        time_str: Time string to check
        format: Time format (default: HH:MM:SS)

    Returns:
        True if the time string is valid, False otherwise
    """
    from datetime import datetime
    
    try:
        datetime.strptime(time_str, format)
        return True
    except ValueError:
        return False


def is_valid_datetime(datetime_str: str, format: str = "%Y-%m-%d %H:%M:%S") -> bool:
    """Check if a datetime string is valid.

    Args:
        datetime_str: Datetime string to check
        format: Datetime format (default: YYYY-MM-DD HH:MM:SS)

    Returns:
        True if the datetime string is valid, False otherwise
    """
    from datetime import datetime
    
    try:
        datetime.strptime(datetime_str, format)
        return True
    except ValueError:
        return False


def is_valid_iso8601(iso8601_str: str) -> bool:
    """Check if a string is a valid ISO 8601 datetime.

    Args:
        iso8601_str: ISO 8601 datetime string to check

    Returns:
        True if the string is a valid ISO 8601 datetime, False otherwise
    """
    from datetime import datetime
    
    try:
        datetime.fromisoformat(iso8601_str.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False
    except AttributeError:
        # For Python < 3.7
        try:
            import dateutil.parser
            dateutil.parser.isoparse(iso8601_str)
            return True
        except (ValueError, ImportError):
            return False
