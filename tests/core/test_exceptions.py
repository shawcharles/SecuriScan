"""
Tests for the Exceptions in the core module.
"""

import pytest

from securiscan.core.exceptions import (
    SecuriScanError,
    ScanError,
    ConfigurationError,
    AuthenticationError,
    ConnectionError,
    ReportingError,
    ValidationError,
    ParsingError,
    TimeoutError,
    RateLimitError,
    ModuleError,
    BrowserError,
    MonitorError,
    NotificationError,
)


class TestSecuriScanError:
    """Tests for the SecuriScanError base class."""

    def test_securiscan_error_initialization(self):
        """Test that SecuriScanError initializes correctly."""
        error = SecuriScanError("Test error message")
        
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details is None
        assert error.cause is None

    def test_securiscan_error_with_details(self):
        """Test that SecuriScanError initializes with details."""
        details = {"key": "value"}
        error = SecuriScanError("Test error message", details=details)
        
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details == details
        assert error.cause is None

    def test_securiscan_error_with_cause(self):
        """Test that SecuriScanError initializes with a cause."""
        cause = ValueError("Original error")
        error = SecuriScanError("Test error message", cause=cause)
        
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details is None
        assert error.cause == cause

    def test_securiscan_error_with_details_and_cause(self):
        """Test that SecuriScanError initializes with details and a cause."""
        details = {"key": "value"}
        cause = ValueError("Original error")
        error = SecuriScanError("Test error message", details=details, cause=cause)
        
        assert str(error) == "Test error message"
        assert error.message == "Test error message"
        assert error.details == details
        assert error.cause == cause


class TestScanError:
    """Tests for the ScanError class."""

    def test_scan_error_initialization(self):
        """Test that ScanError initializes correctly."""
        error = ScanError("Test scan error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test scan error"
        assert error.message == "Test scan error"
        assert error.details == {}
        assert error.cause is None

    def test_scan_error_with_target_url(self):
        """Test that ScanError initializes with a target URL."""
        error = ScanError("Test scan error", target_url="https://example.com")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test scan error"
        assert error.message == "Test scan error"
        assert error.details == {"target_url": "https://example.com"}
        assert error.cause is None
        assert error.target_url == "https://example.com"


class TestConfigurationError:
    """Tests for the ConfigurationError class."""

    def test_configuration_error_initialization(self):
        """Test that ConfigurationError initializes correctly."""
        error = ConfigurationError("Test config error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test config error"
        assert error.message == "Test config error"
        assert error.parameter is None

    def test_configuration_error_with_parameter(self):
        """Test that ConfigurationError initializes with a parameter."""
        error = ConfigurationError("Test config error", parameter="scan_level")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test config error"
        assert error.message == "Test config error"
        assert error.parameter == "scan_level"


class TestAuthenticationError:
    """Tests for the AuthenticationError class."""

    def test_authentication_error_initialization(self):
        """Test that AuthenticationError initializes correctly."""
        error = AuthenticationError("Test authentication error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test authentication error"
        assert error.message == "Test authentication error"
        assert error.details == {}
        assert error.cause is None

    def test_authentication_error_with_auth_type(self):
        """Test that AuthenticationError initializes with an auth type."""
        error = AuthenticationError("Test authentication error", auth_type="basic")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test authentication error"
        assert error.message == "Test authentication error"
        assert error.details == {"auth_type": "basic"}
        assert error.cause is None
        assert error.auth_type == "basic"


class TestConnectionError:
    """Tests for the ConnectionError class."""

    def test_connection_error_initialization(self):
        """Test that ConnectionError initializes correctly."""
        error = ConnectionError("Test network error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test network error"
        assert error.message == "Test network error"
        assert error.url is None

    def test_connection_error_with_url(self):
        """Test that ConnectionError initializes with a URL."""
        error = ConnectionError("Test network error", url="https://example.com")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test network error"
        assert error.message == "Test network error"
        assert error.url == "https://example.com"


class TestReportingError:
    """Tests for the ReportingError class."""

    def test_reporting_error_initialization(self):
        """Test that ReportingError initializes correctly."""
        error = ReportingError("Test reporting error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test reporting error"
        assert error.message == "Test reporting error"
        assert error.details == {}
        assert error.cause is None

    def test_reporting_error_with_format_type(self):
        """Test that ReportingError initializes with a format type."""
        error = ReportingError("Test reporting error", format_type="html")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test reporting error"
        assert error.message == "Test reporting error"
        assert error.details == {"format_type": "html"}
        assert error.cause is None
        assert error.format_type == "html"

    def test_reporting_error_with_output_path(self):
        """Test that ReportingError initializes with an output path."""
        error = ReportingError(
            "Test reporting error",
            format_type="html",
            output_path="/path/to/report.html",
        )
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test reporting error"
        assert error.message == "Test reporting error"
        assert error.details == {
            "format_type": "html",
            "output_path": "/path/to/report.html",
        }
        assert error.cause is None
        assert error.format_type == "html"
        assert error.output_path == "/path/to/report.html"


class TestValidationError:
    """Tests for the ValidationError class."""

    def test_validation_error_initialization(self):
        """Test that ValidationError initializes correctly."""
        error = ValidationError("Test validation error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test validation error"
        assert error.message == "Test validation error"
        assert error.details == {}
        assert error.cause is None

    def test_validation_error_with_field_name(self):
        """Test that ValidationError initializes with a field name."""
        error = ValidationError("Test validation error", field_name="url")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test validation error"
        assert error.message == "Test validation error"
        assert error.details == {"field_name": "url"}
        assert error.cause is None
        assert error.field_name == "url"

    def test_validation_error_with_field_value(self):
        """Test that ValidationError initializes with a field value."""
        error = ValidationError(
            "Test validation error",
            field_name="url",
            field_value="invalid-url",
        )
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test validation error"
        assert error.message == "Test validation error"
        assert error.details == {
            "field_name": "url",
            "field_value": "invalid-url",
        }
        assert error.cause is None
        assert error.field_name == "url"
        assert error.field_value == "invalid-url"


class TestParsingError:
    """Tests for the ParsingError class."""

    def test_parsing_error_initialization(self):
        """Test that ParsingError initializes correctly."""
        error = ParsingError("Test parsing error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test parsing error"
        assert error.message == "Test parsing error"
        assert error.content_type is None

    def test_parsing_error_with_content_type(self):
        """Test that ParsingError initializes with a content type."""
        error = ParsingError("Test parsing error", content_type="json")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test parsing error"
        assert error.message == "Test parsing error"
        assert error.content_type == "json"


class TestTimeoutError:
    """Tests for the TimeoutError class."""

    def test_timeout_error_initialization(self):
        """Test that TimeoutError initializes correctly."""
        error = TimeoutError("Test timeout error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test timeout error"
        assert error.message == "Test timeout error"
        assert error.details == {}
        assert error.cause is None

    def test_timeout_error_with_url(self):
        """Test that TimeoutError initializes with a URL."""
        error = TimeoutError("Test timeout error", url="https://example.com")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test timeout error"
        assert error.message == "Test timeout error"
        assert error.details == {"url": "https://example.com"}
        assert error.cause is None
        assert error.url == "https://example.com"

    def test_timeout_error_with_timeout_value(self):
        """Test that TimeoutError initializes with a timeout value."""
        error = TimeoutError(
            "Test timeout error",
            url="https://example.com",
            timeout=30,
        )
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test timeout error"
        assert error.message == "Test timeout error"
        assert error.details == {
            "url": "https://example.com",
            "timeout": 30,
        }
        assert error.cause is None
        assert error.url == "https://example.com"
        assert error.timeout == 30


class TestRateLimitError:
    """Tests for the RateLimitError class."""

    def test_rate_limit_error_initialization(self):
        """Test that RateLimitError initializes correctly."""
        error = RateLimitError("Test rate limit error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test rate limit error"
        assert error.message == "Test rate limit error"
        assert error.details == {}
        assert error.cause is None

    def test_rate_limit_error_with_url(self):
        """Test that RateLimitError initializes with a URL."""
        error = RateLimitError("Test rate limit error", url="https://example.com")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test rate limit error"
        assert error.message == "Test rate limit error"
        assert error.details == {"url": "https://example.com"}
        assert error.cause is None
        assert error.url == "https://example.com"

    def test_rate_limit_error_with_retry_after(self):
        """Test that RateLimitError initializes with a retry after value."""
        error = RateLimitError(
            "Test rate limit error",
            url="https://example.com",
            retry_after=60,
        )
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test rate limit error"
        assert error.message == "Test rate limit error"
        assert error.details == {
            "url": "https://example.com",
            "retry_after": 60,
        }
        assert error.cause is None
        assert error.url == "https://example.com"
        assert error.retry_after == 60


class TestModuleError:
    """Tests for the ModuleError class."""

    def test_module_error_initialization(self):
        """Test that ModuleError initializes correctly."""
        error = ModuleError("Test module error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test module error"
        assert error.message == "Test module error"
        assert error.module_name is None

    def test_module_error_with_module_name(self):
        """Test that ModuleError initializes with a module name."""
        error = ModuleError("Test module error", module_name="scanner_module")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test module error"
        assert error.message == "Test module error"
        assert error.module_name == "scanner_module"


class TestBrowserError:
    """Tests for the BrowserError class."""

    def test_browser_error_initialization(self):
        """Test that BrowserError initializes correctly."""
        error = BrowserError("Test browser error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test browser error"
        assert error.message == "Test browser error"
        assert error.browser_type is None

    def test_browser_error_with_browser_type(self):
        """Test that BrowserError initializes with a browser type."""
        error = BrowserError("Test browser error", browser_type="chrome")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test browser error"
        assert error.message == "Test browser error"
        assert error.browser_type == "chrome"


class TestMonitorError:
    """Tests for the MonitorError class."""

    def test_monitor_error_initialization(self):
        """Test that MonitorError initializes correctly."""
        error = MonitorError("Test monitor error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test monitor error"
        assert error.message == "Test monitor error"
        assert error.target is None

    def test_monitor_error_with_target(self):
        """Test that MonitorError initializes with a target."""
        error = MonitorError("Test monitor error", target="https://example.com")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test monitor error"
        assert error.message == "Test monitor error"
        assert error.target == "https://example.com"


class TestNotificationError:
    """Tests for the NotificationError class."""

    def test_notification_error_initialization(self):
        """Test that NotificationError initializes correctly."""
        error = NotificationError("Test notification error")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test notification error"
        assert error.message == "Test notification error"
        assert error.notification_type is None

    def test_notification_error_with_notification_type(self):
        """Test that NotificationError initializes with a notification type."""
        error = NotificationError("Test notification error", notification_type="email")
        
        assert isinstance(error, SecuriScanError)
        assert str(error) == "Test notification error"
        assert error.message == "Test notification error"
        assert error.notification_type == "email"
