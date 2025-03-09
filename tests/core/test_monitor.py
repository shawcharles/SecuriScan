import pytest
from unittest.mock import patch, MagicMock
from securiscan.core.monitor import Monitor, MonitorConfig, NotificationConfig
from securiscan.core.result import ScanResult
from securiscan.core.scanner import Scanner
from securiscan.core.config import ScanConfig
from datetime import datetime

# Mock the Scanner and its methods
@pytest.fixture
def mock_scanner():
    with patch('securiscan.core.scanner.Scanner') as MockScanner:
        mock_scanner = MockScanner.return_value
        from securiscan.core.result import ScanTarget, ScanStatistics, ScanResult

        mock_scanner.scan.return_value = ScanResult(
            id="12345",
            target=ScanTarget(url="http://example.com"),
            vulnerabilities=[],
            statistics=ScanStatistics(end_time=datetime.now()),
            scan_config=ScanConfig(),
            version="1.0.0"
        )
        yield mock_scanner

# Mock the logging module
@pytest.fixture
def mock_logger():
    with patch('securiscan.core.monitor.logging') as MockLogging:
        yield MockLogging.getLogger.return_value

# Test Monitor initialization
def test_monitor_initialization(mock_scanner, mock_logger):
    targets = ["http://example.com"]
    interval_hours = 24.0
    scan_config = ScanConfig()
    notify = ["user@example.com"]

    monitor = Monitor(targets, interval_hours, scan_config, notify)

    assert monitor.config.targets == targets
    assert monitor.config.interval_hours == interval_hours
    assert monitor.config.scan_config == scan_config
    assert monitor.config.notifications.email_recipients == notify
    assert monitor.config.notifications.smtp_server == "smtp.example.com"
    assert monitor.config.notifications.smtp_port == 587
    assert monitor.config.notifications.smtp_username == "smtp_user"
    assert monitor.config.notifications.smtp_password == "smtp_pass"
    assert monitor.config.notifications.smtp_use_tls == True
    assert monitor.config.notifications.notify_on_complete == True
    assert monitor.config.notifications.notify_on_error == True

# Test start and stop methods
def test_monitor_start_stop(mock_scanner, mock_logger):
    targets = ["http://example.com"]
    interval_hours = 24.0
    scan_config = ScanConfig()
    notify = ["user@example.com"]

    monitor = Monitor(targets, interval_hours, scan_config, notify)

    # Start the monitor
    monitor.start(run_immediately=True)
    assert monitor.monitor_thread is not None
    assert monitor.monitor_thread.is_alive()

    # Stop the monitor
    monitor.stop()
    assert not monitor.monitor_thread.is_alive()

# Test _send_email_notification method
def test_send_email_notification(mock_scanner, mock_logger):
    targets = ["http://example.com"]
    interval_hours = 24.0
    scan_config = ScanConfig()
    notify = ["user@example.com"]

    monitor = Monitor(targets, interval_hours, scan_config, notify)

    # Mock the SMTP server
    with patch('smtplib.SMTP') as MockSMTP:
        server = MockSMTP.return_value
        result = ScanResult(
            target=MagicMock(url="http://example.com"),
            vulnerabilities=[],
            statistics=MagicMock(end_time=datetime.now())
        )

        # Call the method
        monitor._send_email_notification(result)

        # Check if the SMTP server was used correctly
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("smtp_user", "smtp_pass")
        server.sendmail.assert_called_once_with(
            "smtp_user",
            "user@example.com",
            f"Subject: SecuriScan Alert\n\nScan of {result.target.url} completed.\nVulnerabilities found: 0\nTimestamp: {result.statistics.end_time}\n"
        )
        server.quit.assert_called_once()

# Test _trigger_callbacks method
def test_trigger_callbacks(mock_scanner, mock_logger):
    targets = ["http://example.com"]
    interval_hours = 24.0
    scan_config = ScanConfig()
    notify = ["user@example.com"]

    monitor = Monitor(targets, interval_hours, scan_config, notify)

    # Mock a callback function
    mock_callback = MagicMock()

    # Register the callback
    monitor.on("on_complete", mock_callback)

    # Create a mock result
    result = ScanResult(
        target=MagicMock(url="http://example.com"),
        vulnerabilities=[],
        statistics=MagicMock(end_time=datetime.now())
    )

    # Trigger the callback
    monitor._trigger_callbacks("on_complete", result=result)

    # Check if the callback was called
    mock_callback.assert_called_once_with(result=result)

    # Check if the email notification was sent
    monitor.logger.info.assert_called_with("Email notification sent")
