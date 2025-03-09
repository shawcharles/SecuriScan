"""
Exceptions module for SecuriScan.

This module defines custom exceptions for the SecuriScan framework.
"""

from typing import Optional


class SecuriScanError(Exception):
    """Base exception for all SecuriScan errors."""

    def __init__(self, message: str, details: Optional[dict] = None, cause: Optional[Exception] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            details: Additional details about the error
            cause: Original exception that caused this error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.message = message
        self.details = details
        self.cause = cause
        super().__init__(message, *args)


class ConfigurationError(SecuriScanError):
    """Exception raised for configuration errors."""

    def __init__(self, message: str, parameter: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            parameter: Name of the parameter that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.parameter = parameter
        super().__init__(message, *args, **kwargs)


class ConnectionError(SecuriScanError):
    """Exception raised for connection errors."""

    def __init__(self, message: str, url: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            url: URL that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.url = url
        super().__init__(message, *args, **kwargs)


class ScanError(SecuriScanError):
    """Exception raised for scan errors."""

    def __init__(self, message: str, scan_id: Optional[str] = None, target_url: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            scan_id: ID of the scan that caused the error
            target_url: URL of the target that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.scan_id = scan_id
        self.target_url = target_url
        details = {}
        if target_url:
            details["target_url"] = target_url
        super().__init__(message, details=details, *args, **kwargs)


class ValidationError(SecuriScanError):
    """Exception raised for validation errors."""

    def __init__(self, message: str, field: Optional[str] = None, field_name: Optional[str] = None, field_value: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            field: Name of the field that failed validation
            field_name: Alias for field
            field_value: Value of the field that failed validation
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.field = field
        self.field_name = field_name or field
        self.field_value = field_value
        
        details = {}
        if field_name:
            details["field_name"] = field_name
        if field_value:
            details["field_value"] = field_value
            
        super().__init__(message, details=details, *args, **kwargs)


class AuthenticationError(SecuriScanError):
    """Exception raised for authentication errors."""

    def __init__(self, message: str, auth_type: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            auth_type: Type of authentication that failed
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.auth_type = auth_type
        details = {}
        if auth_type:
            details["auth_type"] = auth_type
        super().__init__(message, details=details, *args, **kwargs)


class RateLimitError(SecuriScanError):
    """Exception raised for rate limiting errors."""

    def __init__(self, message: str, retry_after: Optional[int] = None, url: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            retry_after: Seconds to wait before retrying
            url: URL that triggered the rate limit
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.retry_after = retry_after
        self.url = url
        
        details = {}
        if retry_after:
            details["retry_after"] = retry_after
        if url:
            details["url"] = url
            
        super().__init__(message, details=details, *args, **kwargs)


class TimeoutError(SecuriScanError):
    """Exception raised for timeout errors."""

    def __init__(self, message: str, timeout: Optional[int] = None, url: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            timeout: Timeout value that was exceeded
            url: URL that timed out
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.timeout = timeout
        self.url = url
        
        details = {}
        if timeout:
            details["timeout"] = timeout
        if url:
            details["url"] = url
            
        super().__init__(message, details=details, *args, **kwargs)


class ParsingError(SecuriScanError):
    """Exception raised for parsing errors."""

    def __init__(self, message: str, content_type: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            content_type: Type of content that failed to parse
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.content_type = content_type
        super().__init__(message, *args, **kwargs)


class ModuleError(SecuriScanError):
    """Exception raised for module errors."""

    def __init__(self, message: str, module_name: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            module_name: Name of the module that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.module_name = module_name
        super().__init__(message, *args, **kwargs)


class BrowserError(SecuriScanError):
    """Exception raised for browser automation errors."""

    def __init__(self, message: str, browser_type: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            browser_type: Type of browser that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.browser_type = browser_type
        super().__init__(message, *args, **kwargs)


class MonitorError(SecuriScanError):
    """Exception raised for monitoring errors."""

    def __init__(self, message: str, target: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            target: Target URL that caused the error
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.target = target
        super().__init__(message, *args, **kwargs)


class NotificationError(SecuriScanError):
    """Exception raised for notification errors."""

    def __init__(self, message: str, notification_type: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            notification_type: Type of notification that failed
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.notification_type = notification_type
        super().__init__(message, *args, **kwargs)


class ReportingError(SecuriScanError):
    """Exception raised for reporting errors."""

    def __init__(self, message: str, format_type: Optional[str] = None, output_path: Optional[str] = None, *args, **kwargs):
        """Initialize the exception.

        Args:
            message: Error message
            format_type: Report format that caused the error
            output_path: Path where the report was being written
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
        """
        self.format_type = format_type
        self.output_path = output_path
        
        details = {}
        if format_type:
            details["format_type"] = format_type
        if output_path:
            details["output_path"] = output_path
            
        super().__init__(message, details=details, *args, **kwargs)
