"""
Report Generator Module.

This module provides functionality for generating reports in different formats.
"""

import csv
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from securiscan.core.exceptions import ReportingError
from securiscan.core.result import ScanResult, Severity


class ReportGenerator:
    """Report generator for scan results."""

    def __init__(self, result: ScanResult):
        """Initialize the report generator.

        Args:
            result: Scan result to generate a report for
        """
        self.result = result
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")

    def generate(self, output_path: str, format: str = "html") -> str:
        """Generate a report in the specified format.

        Args:
            output_path: Path to save the report
            format: Report format (html, json, csv, pdf)

        Returns:
            Path to the generated report

        Raises:
            ReportingError: If the format is not supported or there is an error generating the report
        """
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Generate report based on format
        if format.lower() == "html":
            return self._generate_html(output_path)
        elif format.lower() == "json":
            return self._generate_json(output_path)
        elif format.lower() == "csv":
            return self._generate_csv(output_path)
        elif format.lower() == "pdf":
            return self._generate_pdf(output_path)
        else:
            raise ReportingError(f"Unsupported report format: {format}", format_type=format)

    def _generate_html(self, output_path: str) -> str:
        """Generate an HTML report.

        Args:
            output_path: Path to save the report

        Returns:
            Path to the generated report

        Raises:
            ReportingError: If there is an error generating the report
        """
        try:
            # Simple HTML report
            html = f"""<!DOCTYPE html>
<html>
<head>
    <title>SecuriScan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .summary {{ background-color: #f5f5f5; padding: 10px; margin-bottom: 20px; }}
        .vulnerability {{ border: 1px solid #ddd; padding: 10px; margin-bottom: 10px; }}
        .critical {{ border-left: 5px solid #d9534f; }}
        .high {{ border-left: 5px solid #f0ad4e; }}
        .medium {{ border-left: 5px solid #5bc0de; }}
        .low {{ border-left: 5px solid #5cb85c; }}
        .info {{ border-left: 5px solid #5bc0de; }}
    </style>
</head>
<body>
    <h1>SecuriScan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Target: {self.result.target.url}</p>
        <p>Scan Date: {self.result.created_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Scan Duration: {self.result.duration:.2f} seconds</p>
        <p>Vulnerabilities Found: {len(self.result.vulnerabilities)}</p>
    </div>
    <h2>Vulnerabilities</h2>
"""

            # Add vulnerabilities
            if self.result.vulnerabilities:
                for vuln in self.result.vulnerabilities:
                    html += f"""
    <div class="vulnerability {vuln.severity.lower()}">
        <h3>{vuln.name}</h3>
        <p><strong>Severity:</strong> {vuln.severity}</p>
        <p><strong>URL:</strong> {vuln.url}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        <p><strong>Remediation:</strong> {vuln.remediation}</p>
    </div>
"""
            else:
                html += "<p>No vulnerabilities found.</p>"

            html += """
</body>
</html>
"""

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

            return output_path
        except Exception as e:
            raise ReportingError(f"Error generating HTML report: {str(e)}", format_type="html")

    def _generate_json(self, output_path: str) -> str:
        """Generate a JSON report.

        Args:
            output_path: Path to save the report

        Returns:
            Path to the generated report

        Raises:
            ReportingError: If there is an error generating the report
        """
        try:
            # Convert result to JSON
            result_dict = self.result.dict()
            
            # Convert datetime objects to strings
            def convert_datetime(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                return str(obj)
            
            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, default=convert_datetime, indent=2)
            
            return output_path
        except Exception as e:
            raise ReportingError(f"Error generating JSON report: {str(e)}", format_type="json")

    def _generate_csv(self, output_path: str) -> str:
        """Generate a CSV report.

        Args:
            output_path: Path to save the report

        Returns:
            Path to the generated report

        Raises:
            ReportingError: If there is an error generating the report
        """
        try:
            # Write vulnerabilities to CSV
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "ID", "Name", "Type", "Severity", "Confidence", 
                    "URL", "Description", "Remediation", "CWE"
                ])
                
                for vuln in self.result.vulnerabilities:
                    writer.writerow([
                        vuln.id,
                        vuln.name,
                        vuln.type,
                        vuln.severity,
                        vuln.confidence,
                        vuln.url,
                        vuln.description,
                        vuln.remediation,
                        vuln.cwe or ""
                    ])
            
            return output_path
        except Exception as e:
            raise ReportingError(f"Error generating CSV report: {str(e)}", format_type="csv")

    def _generate_pdf(self, output_path: str) -> str:
        """Generate a PDF report.

        Args:
            output_path: Path to save the report

        Returns:
            Path to the generated report

        Raises:
            ReportingError: If there is an error generating the report
        """
        try:
            # For this simple implementation, we'll just create a text file with a .pdf extension
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"SecuriScan Report\n")
                f.write(f"===============\n\n")
                f.write(f"Target: {self.result.target.url}\n")
                f.write(f"Scan Date: {self.result.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Scan Duration: {self.result.duration:.2f} seconds\n")
                f.write(f"Vulnerabilities Found: {len(self.result.vulnerabilities)}\n\n")
                
                f.write(f"Vulnerabilities\n")
                f.write(f"==============\n\n")
                
                if self.result.vulnerabilities:
                    for vuln in self.result.vulnerabilities:
                        f.write(f"{vuln.name} ({vuln.severity})\n")
                        f.write(f"URL: {vuln.url}\n")
                        f.write(f"Description: {vuln.description}\n")
                        f.write(f"Remediation: {vuln.remediation}\n\n")
                else:
                    f.write("No vulnerabilities found.\n")
            
            return output_path
        except Exception as e:
            raise ReportingError(f"Error generating PDF report: {str(e)}", format_type="pdf")
