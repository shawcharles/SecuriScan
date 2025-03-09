"""
Tests for the ReportGenerator class in the reporting module.
"""

import json
import os
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, mock_open

from securiscan.reporting.generator import ReportGenerator
from securiscan.core.exceptions import ReportingError
from securiscan.core.result import (
    ScanResult,
    ScanTarget,
    ScanStatistics,
    Vulnerability,
    Severity,
    Confidence,
    VulnerabilityType,
    Evidence,
)


class TestReportGenerator:
    """Tests for the ReportGenerator class."""

    def test_report_generator_initialization(self):
        """Test that ReportGenerator initializes correctly."""
        # Create a mock scan result
        mock_result = MagicMock(spec=ScanResult)
        
        # Create a report generator
        generator = ReportGenerator(mock_result)
        
        assert generator.result == mock_result
        assert generator.template_dir is not None

    def test_generate_html_report(self, temp_report_dir):
        """Test that generate method creates an HTML report."""
        # Create a mock scan result
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level="standard",
        )
        
        # Create a vulnerability
        evidence = Evidence(
            type="test_evidence",
            data={"test_key": "test_value"},
            description="Test evidence description",
        )
        
        vulnerability = Vulnerability(
            id="test-vuln-001",
            name="Test Vulnerability",
            type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="This is a test vulnerability",
            url="https://example.com/vulnerable-page",
            path="/vulnerable-page",
            parameter="q",
            evidence=[evidence],
            remediation="Fix the vulnerability by implementing proper input validation",
            references=["https://owasp.org/www-project-top-ten/"],
            cwe=79,
            tags={"xss", "injection", "test"},
        )
        
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[vulnerability],
            statistics=statistics,
            scan_config={"scan_level": "standard"},
            version="0.1.0",
        )
        
        # Create a report generator
        generator = ReportGenerator(result)
        
        # Generate an HTML report
        report_path = os.path.join(temp_report_dir, "report.html")
        
        # Mock the open function to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file:
            generator.generate(report_path, "html")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w", encoding="utf-8")
            
            # Check that HTML content was written
            handle = mock_file()
            handle.write.assert_called()
            
            # Get the HTML content
            calls = handle.write.call_args_list
            html_content = "".join(call[0][0] for call in calls)
            
            # Check that the HTML content contains expected elements
            assert "<html" in html_content
            assert "<body" in html_content
            assert "SecuriScan Report" in html_content
            assert "https://example.com" in html_content
            assert "Test Vulnerability" in html_content
            assert "HIGH" in html_content
            assert "This is a test vulnerability" in html_content
            assert "Fix the vulnerability by implementing proper input validation" in html_content

    def test_generate_json_report(self, temp_report_dir):
        """Test that generate method creates a JSON report."""
        # Create a mock scan result
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level="standard",
        )
        
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[],
            statistics=statistics,
            scan_config={"scan_level": "standard"},
            version="0.1.0",
        )
        
        # Create a report generator
        generator = ReportGenerator(result)
        
        # Generate a JSON report
        report_path = os.path.join(temp_report_dir, "report.json")
        
        # Mock the open function and json.dump to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file, \
             patch("json.dump") as mock_json_dump:
            generator.generate(report_path, "json")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w", encoding="utf-8")
            
            # Check that json.dump was called with the result dict
            mock_json_dump.assert_called_once()
            args, kwargs = mock_json_dump.call_args
            assert args[0] == result.dict()
            assert kwargs["default"] is not None  # Should have a default serializer
            assert kwargs["indent"] == 2

    def test_generate_csv_report(self, temp_report_dir):
        """Test that generate method creates a CSV report."""
        # Create a mock scan result
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level="standard",
        )
        
        # Create a vulnerability
        vulnerability = Vulnerability(
            id="test-vuln-001",
            name="Test Vulnerability",
            type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="This is a test vulnerability",
            url="https://example.com/vulnerable-page",
            path="/vulnerable-page",
            parameter="q",
            remediation="Fix the vulnerability",
            cwe=79,
        )
        
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[vulnerability],
            statistics=statistics,
            scan_config={"scan_level": "standard"},
            version="0.1.0",
        )
        
        # Create a report generator
        generator = ReportGenerator(result)
        
        # Generate a CSV report
        report_path = os.path.join(temp_report_dir, "report.csv")
        
        # Mock the open function and csv.writer to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file, \
             patch("csv.writer") as mock_csv_writer:
            mock_writer = MagicMock()
            mock_csv_writer.return_value = mock_writer
            
            generator.generate(report_path, "csv")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w", newline="", encoding="utf-8")
            
            # Check that csv.writer was called
            mock_csv_writer.assert_called_once()
            
            # Check that the header row was written
            mock_writer.writerow.assert_called()
            
            # Check that the vulnerability row was written
            assert mock_writer.writerow.call_count >= 2

    def test_generate_pdf_report(self, temp_report_dir):
        """Test that generate method creates a PDF report."""
        # Create a mock scan result
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        statistics = ScanStatistics(
            start_time=datetime.now(),
            scan_level="standard",
        )
        
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[],
            statistics=statistics,
            scan_config={"scan_level": "standard"},
            version="0.1.0",
        )
        
        # Create a report generator
        generator = ReportGenerator(result)
        
        # Generate a PDF report
        report_path = os.path.join(temp_report_dir, "report.pdf")
        
        # Mock the open function to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file:
            generator.generate(report_path, "pdf")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w", encoding="utf-8")
            
            # Check that some content was written
            handle = mock_file()
            handle.write.assert_called()

    def test_generate_unsupported_format(self, temp_report_dir):
        """Test that generate method raises an error for unsupported formats."""
        # Create a mock scan result
        mock_result = MagicMock(spec=ScanResult)
        
        # Create a report generator
        generator = ReportGenerator(mock_result)
        
        # Generate a report with an unsupported format
        report_path = os.path.join(temp_report_dir, "report.xyz")
        
        # Check that an error is raised
        with pytest.raises(ReportingError) as excinfo:
            generator.generate(report_path, "xyz")
        
        # Check the error message
        assert "Unsupported report format: xyz" in str(excinfo.value)
        assert excinfo.value.format_type == "xyz"
        assert excinfo.value.output_path == report_path

    def test_generate_with_nonexistent_directory(self, temp_report_dir):
        """Test that generate method creates directories if they don't exist."""
        # Create a mock scan result
        mock_result = MagicMock(spec=ScanResult)
        
        # Create a report generator
        generator = ReportGenerator(mock_result)
        
        # Generate a report in a nonexistent directory
        nonexistent_dir = os.path.join(temp_report_dir, "nonexistent")
        report_path = os.path.join(nonexistent_dir, "report.html")
        
        # Mock os.makedirs and open to avoid actually creating directories and files
        with patch("os.makedirs") as mock_makedirs, \
             patch("builtins.open", mock_open()) as mock_file:
            generator.generate(report_path, "html")
            
            # Check that the directory was created
            mock_makedirs.assert_called_once_with(nonexistent_dir, exist_ok=True)
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w", encoding="utf-8")
