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

from jinja2 import Environment, FileSystemLoader, select_autoescape

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
            # Set up Jinja2 environment
            env = Environment(
                loader=FileSystemLoader(self.template_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
            
            # If template doesn't exist, use a default template
            template_path = os.path.join(self.template_dir, "report.html")
            if not os.path.exists(template_path):
                template_content = self._get_default_html_template()
                os.makedirs(os.path.dirname(template_path), exist_ok=True)
                with open(template_path, "w") as f:
                    f.write(template_content)
            
            # Load template
            template = env.get_template("report.html")
            
            # Prepare data for template
            data = self._prepare_template_data()
            
            # Render template
            html = template.render(**data)
            
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
            json_data = self.result.to_json(pretty=True)
            
            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_data)
            
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
            # Prepare data for CSV
            vulnerabilities = self.result.vulnerabilities
            
            if not vulnerabilities:
                # Create empty CSV with headers
                with open(output_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "ID", "Name", "Type", "Severity", "Confidence", 
                        "URL", "Description", "Remediation", "CWE"
                    ])
                return output_path
            
            # Write vulnerabilities to CSV
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "ID", "Name", "Type", "Severity", "Confidence", 
                    "URL", "Description", "Remediation", "CWE"
                ])
                
                for vuln in vulnerabilities:
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
            # Check if reportlab is installed
            try:
                from reportlab.lib import colors
                from reportlab.lib.pagesizes import letter
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            except ImportError:
                raise ReportingError(
                    "reportlab is required for PDF generation. Install it with: pip install reportlab",
                    format_type="pdf"
                )
            
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = []
            
            # Add title
            title_style = styles["Title"]
            elements.append(Paragraph(f"Security Scan Report: {self.result.target.url}", title_style))
            elements.append(Spacer(1, 12))
            
            # Add summary
            elements.append(Paragraph("Summary", styles["Heading1"]))
            elements.append(Spacer(1, 6))
            
            summary_data = [
                ["Target URL", str(self.result.target.url)],
                ["Scan Date", self.result.created_at.strftime("%Y-%m-%d %H:%M:%S")],
                ["Risk Level", f"{self.result.risk_level} ({self.result.risk_score:.1f}/100)"],
                ["Vulnerabilities", str(len(self.result.vulnerabilities))],
                ["Scan Duration", f"{self.result.statistics.duration_seconds:.2f} seconds"],
            ]
            
            summary_table = Table(summary_data, colWidths=[120, 350])
            summary_table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            
            elements.append(summary_table)
            elements.append(Spacer(1, 12))
            
            # Add vulnerabilities
            if self.result.vulnerabilities:
                elements.append(Paragraph("Vulnerabilities", styles["Heading1"]))
                elements.append(Spacer(1, 6))
                
                # Define severity colors
                severity_colors = {
                    "critical": colors.red,
                    "high": colors.orangered,
                    "medium": colors.orange,
                    "low": colors.green,
                    "info": colors.blue,
                }
                
                # Sort vulnerabilities by severity
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                sorted_vulns = sorted(
                    self.result.vulnerabilities,
                    key=lambda v: severity_order.get(v.severity.lower(), 999)
                )
                
                # Add each vulnerability
                for i, vuln in enumerate(sorted_vulns, 1):
                    # Add vulnerability header
                    severity_color = severity_colors.get(vuln.severity.lower(), colors.black)
                    vuln_title_style = ParagraphStyle(
                        name=f"VulnTitle{i}",
                        parent=styles["Heading2"],
                        textColor=severity_color,
                    )
                    elements.append(Paragraph(f"{i}. [{vuln.severity.upper()}] {vuln.name}", vuln_title_style))
                    elements.append(Spacer(1, 6))
                    
                    # Add vulnerability details
                    vuln_data = [
                        ["Type", str(vuln.type)],
                        ["URL", str(vuln.url)],
                        ["Confidence", str(vuln.confidence)],
                        ["Description", vuln.description],
                        ["Remediation", vuln.remediation],
                    ]
                    
                    if vuln.cwe:
                        vuln_data.append(["CWE", str(vuln.cwe)])
                    
                    vuln_table = Table(vuln_data, colWidths=[100, 370])
                    vuln_table.setStyle(TableStyle([
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('PADDING', (0, 0), (-1, -1), 6),
                    ]))
                    
                    elements.append(vuln_table)
                    elements.append(Spacer(1, 12))
            else:
                elements.append(Paragraph("No vulnerabilities found.", styles["Normal"]))
            
            # Build PDF
            doc.build(elements)
            
            return output_path
        except Exception as e:
            raise ReportingError(f"Error generating PDF report: {str(e)}", format_type="pdf")

    def _prepare_template_data(self) -> Dict[str, Any]:
        """Prepare data for the HTML template.

        Returns:
            Dictionary of template data
        """
        # Count vulnerabilities by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for vuln in self.result.vulnerabilities:
            severity_counts[vuln.severity.lower()] += 1
        
        # Sort vulnerabilities by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_vulns = sorted(
            self.result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity.lower(), 999)
        )
        
        # Prepare data
        return {
            "title": f"Security Scan Report: {self.result.target.url}",
            "target": self.result.target,
            "scan_date": self.result.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": self.result.risk_level,
            "risk_score": self.result.risk_score,
            "vulnerabilities": sorted_vulns,
            "severity_counts": severity_counts,
            "statistics": self.result.statistics,
            "version": self.result.version,
        }

    def _get_default_html_template(self) -> str:
        """Get the default HTML template.

        Returns:
            Default HTML template content
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
        }
        .summary-table th, .summary-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .summary-table th {
            background-color: #f2f2f2;
        }
        .severity-counts {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 20px;
        }
        .severity-badge {
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
        }
        .critical { background-color: #dc3545; }
        .high { background-color: #fd7e14; }
        .medium { background-color: #ffc107; color: #333; }
        .low { background-color: #28a745; }
        .info { background-color: #17a2b8; }
        .vulnerability {
            border: 1px solid #dee2e6;
            border-radius: 4px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .vulnerability-header {
            padding: 10px 15px;
            font-weight: bold;
            color: white;
        }
        .vulnerability-body {
            padding: 15px;
        }
        .vulnerability-table {
            width: 100%;
            border-collapse: collapse;
        }
        .vulnerability-table th, .vulnerability-table td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .vulnerability-table th {
            width: 150px;
            background-color: #f2f2f2;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated on {{ scan_date }}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table class="summary-table">
            <tr>
                <th>Target URL</th>
                <td>{{ target.url }}</td>
            </tr>
            <tr>
                <th>Risk Level</th>
                <td>{{ risk_level }} ({{ "%.1f"|format(risk_score) }}/100)</td>
            </tr>
            <tr>
                <th>Scan Duration</th>
                <td>{{ "%.2f"|format(statistics.duration_seconds) }} seconds</td>
            </tr>
            <tr>
                <th>URLs Discovered</th>
                <td>{{ statistics.urls_discovered }}</td>
            </tr>
            <tr>
                <th>URLs Scanned</th>
                <td>{{ statistics.urls_scanned }}</td>
            </tr>
            <tr>
                <th>Requests Sent</th>
                <td>{{ statistics.requests_sent }}</td>
            </tr>
            <tr>
                <th>Vulnerabilities Found</th>
                <td>{{ vulnerabilities|length }}</td>
            </tr>
        </table>
    </div>
    
    <div class="severity-counts">
        {% if severity_counts.critical > 0 %}
        <div class="severity-badge critical">Critical: {{ severity_counts.critical }}</div>
        {% endif %}
        {% if severity_counts.high > 0 %}
        <div class="severity-badge high">High: {{ severity_counts.high }}</div>
        {% endif %}
        {% if severity_counts.medium > 0 %}
        <div class="severity-badge medium">Medium: {{ severity_counts.medium }}</div>
        {% endif %}
        {% if severity_counts.low > 0 %}
        <div class="severity-badge low">Low: {{ severity_counts.low }}</div>
        {% endif %}
        {% if severity_counts.info > 0 %}
        <div class="severity-badge info">Info: {{ severity_counts.info }}</div>
        {% endif %}
    </div>
    
    <h2>Vulnerabilities</h2>
    
    {% if vulnerabilities %}
        {% for vuln in vulnerabilities %}
            <div class="vulnerability">
                <div class="vulnerability-header {{ vuln.severity|lower }}">
                    {{ loop.index }}. [{{ vuln.severity|upper }}] {{ vuln.name }}
                </div>
                <div class="vulnerability-body">
                    <table class="vulnerability-table">
                        <tr>
                            <th>Type</th>
                            <td>{{ vuln.type }}</td>
                        </tr>
                        <tr>
                            <th>URL</th>
                            <td>{{ vuln.url }}</td>
                        </tr>
                        <tr>
                            <th>Confidence</th>
                            <td>{{ vuln.confidence }}</td>
                        </tr>
                        <tr>
                            <th>Description</th>
                            <td>{{ vuln.description }}</td>
                        </tr>
                        <tr>
                            <th>Remediation</th>
                            <td>{{ vuln.remediation }}</td>
                        </tr>
                        {% if vuln.cwe %}
                        <tr>
                            <th>CWE</th>
                            <td>{{ vuln.cwe }}</td>
                        </tr>
                        {% endif %}
                        {% if vuln.references %}
                        <tr>
                            <th>References</th>
                            <td>
                                <ul>
                                    {% for ref in vuln.references %}
                                    <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                                    {% endfor %}
                                </ul>
                            </td>
                        </tr>
                        {% endif %}
                    </table>
                </div>
            </div>
        {% endfor %}
    {% else %}
        <p>No vulnerabilities found.</p>
    {% endif %}
    
    <div class="footer">
        <p>Generated by SecuriScan v{{ version }}</p>
        <p>This report is for authorized security assessment purposes only.</p>
    </div>
</body>
</html>
"""
