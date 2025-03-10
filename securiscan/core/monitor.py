"""
Monitor module for SecuriScan.

This module provides functionality for continuous security monitoring.
"""

import logging
import time
from datetime import datetime, timedelta
from threading import Event, Thread
from typing import Callable, Dict, List, Optional, Union

from pydantic import BaseModel, EmailStr, Field, HttpUrl

from securiscan.core.config import ScanConfig, NotificationConfig
from securiscan.core.result import ScanResult
from securiscan.core.scanner import Scanner


class MonitorConfig(BaseModel):
    """Configuration for the monitor."""

    targets: List[str]
    interval_hours: float = 24.0
    scan_config: Optional[ScanConfig] = None
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    max_history: int = 10
    auto_remediation: bool = False


class Monitor:
    """Continuous security monitoring for websites."""

    def __init__(
        self,
        targets: Union[str, List[str]],
        interval_hours: float = 24.0,
        scan_config: Optional[ScanConfig] = None,
        notify: Optional[List[str]] = None,
    ):
        """Initialize the monitor.

        Args:
            targets: URL or list of URLs to monitor
            interval_hours: Monitoring interval in hours
            scan_config: Scan configuration
            notify: List of email addresses to notify
        """
        # Convert single target to list
        if isinstance(targets, str):
            targets = [targets]

        # Create notification config if emails provided
        notifications = NotificationConfig()
        if notify:
            notifications.enable_email(
                recipient_email=notify[0],
                smtp_server="smtp.example.com",
                smtp_port=587,
                smtp_username="smtp_user",
                smtp_password="smtp_pass",
                smtp_use_tls=True,
            )

        # Create monitor config
        self.config = MonitorConfig(
            targets=targets,
            interval_hours=interval_hours,
            scan_config=scan_config or ScanConfig(),
            notifications=notifications,
        )

        self.logger = logging.getLogger("securiscan.monitor")
        self.scanner = Scanner(self.config.scan_config)
        self.history: Dict[str, List[ScanResult]] = {target: [] for target in targets}
        self.stop_event = Event()
        self.monitor_thread: Optional[Thread] = None
        self.callbacks: Dict[str, List[Callable]] = {
            "on_start": [],
            "on_complete": [],
            "on_error": [],
            "on_new_vulnerabilities": [],
        }

    def _send_email_notification(self, result: ScanResult) -> None:
        """Send an email notification for a scan result.

        Args:
            result: Scan result
        """
        if not self.config.notifications.email_enabled:
            return

        # Construct the email message
        message = f"Subject: SecuriScan Alert\n\nScan of {result.target.url} completed.\n"
        message += f"Vulnerabilities found: {len(result.vulnerabilities)}\n"
        message += f"Timestamp: {result.statistics.end_time}\n"

        # Send the email
        with smtplib.SMTP(self.config.notifications.smtp_server, self.config.notifications.smtp_port) as server:
            server.starttls()
            server.login(self.config.notifications.smtp_username, self.config.notifications.smtp_password)
            server.sendmail(
                self.config.notifications.smtp_username,
                self.config.notifications.recipient_email,
                message,
            )
        self.logger.info("Email notification sent")

    def start(self, run_immediately: bool = True) -> None:
        """Start the monitoring process.

        Args:
            run_immediately: Whether to run the first scan immediately
        """
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.logger.warning("Monitor is already running")
            return

        self.stop_event.clear()
        self.monitor_thread = Thread(target=self._monitoring_loop, args=(run_immediately,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.logger.info(
            f"Started monitoring {len(self.config.targets)} targets every {self.config.interval_hours} hours"
        )

    def stop(self) -> None:
        """Stop the monitoring process."""
        if not self.monitor_thread or not self.monitor_thread.is_alive():
            self.logger.warning("Monitor is not running")
            return

        self.logger.info("Stopping monitor...")
        self.stop_event.set()
        self.monitor_thread.join(timeout=30)
        self.logger.info("Monitor stopped")

    def _monitoring_loop(self, run_immediately: bool) -> None:
        """Main monitoring loop.

        Args:
            run_immediately: Whether to run the first scan immediately
        """
        if not run_immediately:
            # Wait for the first interval
            self._sleep_until_next_scan()

        while not self.stop_event.is_set():
            for target in self.config.targets:
                if self.stop_event.is_set():
                    break

                try:
                    self._trigger_callbacks("on_start", target=target)
                    self.logger.info(f"Starting scan of {target}")

                    # Run the scan
                    result = self.scanner.scan(target)

                    # Process the result
                    self._process_scan_result(target, result)

                    self._trigger_callbacks("on_complete", target=target, result=result)
                    self.logger.info(
                        f"Completed scan of {target}: {len(result.vulnerabilities)} vulnerabilities found"
                    )
                except Exception as e:
                    self.logger.error(f"Error scanning {target}: {str(e)}", exc_info=True)
                    self._trigger_callbacks("on_error", target=target, error=e)

            # Wait for the next interval
            if not self._sleep_until_next_scan():
                break

    def _sleep_until_next_scan(self) -> bool:
        """Sleep until the next scan is due.

        Returns:
            False if stopped during sleep, True otherwise
        """
        # Calculate sleep time in seconds
        sleep_time = self.config.interval_hours * 3600
        end_time = time.time() + sleep_time

        # Sleep in small increments to allow for clean shutdown
        while time.time() < end_time:
            if self.stop_event.is_set():
                return False
            time.sleep(min(10, end_time - time.time()))

        return True

    def _process_scan_result(self, target: str, result: ScanResult) -> None:
        """Process a scan result.

        Args:
            target: Target URL
            result: Scan result
        """
        # Add to history
        self.history[target].append(result)

        # Trim history if needed
        if len(self.history[target]) > self.config.max_history:
            self.history[target] = self.history[target][-self.config.max_history :]

        # Check for new vulnerabilities
        if len(self.history[target]) > 1:
            previous_result = self.history[target][-2]
            new_vulnerabilities = self._find_new_vulnerabilities(previous_result, result)

            if new_vulnerabilities:
                self.logger.info(
                    f"Found {len(new_vulnerabilities)} new vulnerabilities for {target}"
                )
                self._trigger_callbacks(
                    "on_new_vulnerabilities",
                    target=target,
                    result=result,
                    new_vulnerabilities=new_vulnerabilities,
                )

    def _find_new_vulnerabilities(
        self, previous_result: ScanResult, current_result: ScanResult
    ) -> List:
        """Find new vulnerabilities between two scan results.

        Args:
            previous_result: Previous scan result
            current_result: Current scan result

        Returns:
            List of new vulnerabilities
        """
        # Get IDs of previous vulnerabilities
        previous_ids = {v.id for v in previous_result.vulnerabilities}

        # Find vulnerabilities that weren't in the previous scan
        new_vulnerabilities = [
            v for v in current_result.vulnerabilities if v.id not in previous_ids
        ]

        return new_vulnerabilities

    def on(self, event: str, callback: Callable) -> None:
        """Register a callback for an event.

        Args:
            event: Event name (on_start, on_complete, on_error, on_new_vulnerabilities)
            callback: Callback function

        Raises:
            ValueError: If the event is not valid
        """
        if event not in self.callbacks:
            raise ValueError(
                f"Invalid event: {event}. Valid events: {', '.join(self.callbacks.keys())}"
            )

        self.callbacks[event].append(callback)
        self.logger.debug(f"Registered callback for event: {event}")

    def _trigger_callbacks(self, event: str, **kwargs) -> None:
        """Trigger callbacks for an event.

        Args:
            event: Event name
            **kwargs: Arguments to pass to the callbacks
        """
        for callback in self.callbacks.get(event, []):
            try:
                callback(**kwargs)
            except Exception as e:
                self.logger.error(f"Error in {event} callback: {str(e)}", exc_info=True)

        if event == "on_complete" and self.config.notifications.notify_on_complete:
            self._send_email_notification(kwargs["result"])

        if event == "on_error" and self.config.notifications.notify_on_error:
            self._send_email_notification(kwargs["result"])

    def get_last_result(self, target: str) -> Optional[ScanResult]:
        """Get the most recent scan result for a target.

        Args:
            target: Target URL

        Returns:
            Most recent scan result, or None if no scans have been performed

        Raises:
            ValueError: If the target is not being monitored
        """
        if target not in self.history:
            raise ValueError(f"Target not found: {target}")

        if not self.history[target]:
            return None

        return self.history[target][-1]

    def get_history(self, target: str) -> List[ScanResult]:
        """Get the scan history for a target.

        Args:
            target: Target URL

        Returns:
            List of scan results

        Raises:
            ValueError: If the target is not being monitored
        """
        if target not in self.history:
            raise
