"""
Content Analysis Scanner Module.

This module analyzes website content for security issues.
"""

import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from securiscan.core.result import (
    Confidence,
    Evidence,
    ScanTarget,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from securiscan.core.scanner import BaseScanner
from securiscan.utils.http import extract_urls_from_html


class ContentAnalysisScanner(BaseScanner):
    """Scanner for analyzing website content for security issues."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the content analysis scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Analyzing content for {target.url}")
        vulnerabilities = []

        try:
            # Send request to the target
            response = self.scanner.send_request(target.url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Check for sensitive information in HTML comments
            comment_issues = self._check_html_comments(soup)
            if comment_issues:
                vuln = self._create_sensitive_comments_vulnerability(target.url, comment_issues)
                vulnerabilities.append(vuln)
            
            # Check for mixed content
            if target.scheme == "https":
                mixed_content = self._check_mixed_content(soup, str(target.url))
                if mixed_content:
                    vuln = self._create_mixed_content_vulnerability(target.url, mixed_content)
                    vulnerabilities.append(vuln)
            
            # Check for insecure forms
            insecure_forms = self._check_insecure_forms(soup, target.scheme)
            if insecure_forms:
                vuln = self._create_insecure_forms_vulnerability(target.url, insecure_forms)
                vulnerabilities.append(vuln)
            
            # Check for password inputs in non-secure context
            if target.scheme != "https":
                password_inputs = self._check_password_inputs(soup)
                if password_inputs:
                    vuln = self._create_password_over_http_vulnerability(target.url, password_inputs)
                    vulnerabilities.append(vuln)
            
            # Check for sensitive files
            sensitive_links = self._check_sensitive_files(soup, str(target.url))
            if sensitive_links:
                vuln = self._create_sensitive_files_vulnerability(target.url, sensitive_links)
                vulnerabilities.append(vuln)
            
            # Check for error messages
            error_messages = self._check_error_messages(soup, response.text)
            if error_messages:
                vuln = self._create_error_messages_vulnerability(target.url, error_messages)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error analyzing content: {str(e)}", exc_info=True)
            return []

    def _check_html_comments(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Check for sensitive information in HTML comments.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of issues found
        """
        issues = []
        
        # Find all comments
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith("<!--"))
        
        # Define patterns for sensitive information
        sensitive_patterns = [
            (r"password\s*[=:]\s*['\"](.*?)['\"]", "Password"),
            (r"username\s*[=:]\s*['\"](.*?)['\"]", "Username"),
            (r"api[_\s]*key\s*[=:]\s*['\"](.*?)['\"]", "API Key"),
            (r"secret\s*[=:]\s*['\"](.*?)['\"]", "Secret"),
            (r"token\s*[=:]\s*['\"](.*?)['\"]", "Token"),
            (r"database\s*[=:]\s*['\"](.*?)['\"]", "Database"),
            (r"todo", "TODO Comment"),
            (r"fixme", "FIXME Comment"),
            (r"bug", "BUG Comment"),
            (r"hack", "HACK Comment"),
            (r"workaround", "Workaround Comment"),
            (r"@author", "Author Information"),
            (r"@version", "Version Information"),
        ]
        
        for comment in comments:
            comment_text = comment.strip()
            
            # Skip empty comments
            if len(comment_text) <= 7:  # <!--  -->
                continue
            
            # Check for sensitive patterns
            for pattern, issue_type in sensitive_patterns:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    # Truncate long comments
                    if len(comment_text) > 150:
                        display_text = comment_text[:147] + "..."
                    else:
                        display_text = comment_text
                    
                    issues.append({
                        "type": issue_type,
                        "comment": display_text,
                    })
                    break
        
        return issues

    def _check_mixed_content(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, str]]:
        """Check for mixed content (HTTP resources on HTTPS page).

        Args:
            soup: BeautifulSoup object
            base_url: Base URL of the page

        Returns:
            List of mixed content issues
        """
        mixed_content = []
        
        # Check for HTTP resources in various tags
        for tag_name, attr in [
            ("img", "src"),
            ("script", "src"),
            ("link", "href"),
            ("iframe", "src"),
            ("audio", "src"),
            ("video", "src"),
            ("source", "src"),
            ("object", "data"),
            ("embed", "src"),
        ]:
            for tag in soup.find_all(tag_name, attrs={attr: True}):
                url = tag[attr]
                if url.startswith("http:"):
                    mixed_content.append({
                        "tag": tag_name,
                        "attribute": attr,
                        "url": url,
                    })
        
        # Check for HTTP URLs in inline styles
        for tag in soup.find_all(style=True):
            style = tag["style"]
            urls = re.findall(r"url\(['\"]?(http:.*?)['\"]?\)", style)
            for url in urls:
                mixed_content.append({
                    "tag": tag.name,
                    "attribute": "style",
                    "url": url,
                })
        
        # Check for HTTP URLs in style tags
        for style_tag in soup.find_all("style"):
            if style_tag.string:
                urls = re.findall(r"url\(['\"]?(http:.*?)['\"]?\)", style_tag.string)
                for url in urls:
                    mixed_content.append({
                        "tag": "style",
                        "attribute": "content",
                        "url": url,
                    })
        
        return mixed_content

    def _check_insecure_forms(self, soup: BeautifulSoup, scheme: str) -> List[Dict[str, str]]:
        """Check for insecure forms.

        Args:
            soup: BeautifulSoup object
            scheme: URL scheme (http or https)

        Returns:
            List of insecure form issues
        """
        insecure_forms = []
        
        # Find all forms
        forms = soup.find_all("form")
        
        for form in forms:
            issues = []
            
            # Check for insecure action URL
            action = form.get("action", "")
            if action.startswith("http:"):
                issues.append("Form submits to HTTP URL")
            
            # Check for missing or insecure method
            method = form.get("method", "get").lower()
            if method == "get" and self._form_has_sensitive_fields(form):
                issues.append("Form uses GET method with sensitive fields")
            
            # Check for autocomplete on sensitive fields
            password_fields = form.find_all("input", type="password")
            for field in password_fields:
                if field.get("autocomplete") != "off":
                    issues.append("Password field with autocomplete enabled")
                    break
            
            # If using HTTPS, check for missing security attributes
            if scheme == "https":
                if not form.get("autocomplete") == "off":
                    if self._form_has_sensitive_fields(form):
                        issues.append("Form with sensitive fields missing autocomplete=off")
            
            # If form has issues, add to the list
            if issues:
                insecure_forms.append({
                    "action": action or "(current page)",
                    "method": method,
                    "issues": issues,
                })
        
        return insecure_forms

    def _form_has_sensitive_fields(self, form: BeautifulSoup) -> bool:
        """Check if a form has sensitive fields.

        Args:
            form: Form element

        Returns:
            True if the form has sensitive fields, False otherwise
        """
        sensitive_types = ["password", "email", "tel", "number", "credit", "card"]
        sensitive_names = ["password", "email", "username", "user", "login", "account", "card", 
                          "credit", "ssn", "social", "dob", "birth", "phone", "mobile", "address"]
        
        # Check input types
        for input_type in sensitive_types:
            if form.find("input", type=input_type):
                return True
        
        # Check input names
        for input_tag in form.find_all("input"):
            name = input_tag.get("name", "").lower()
            if any(sensitive in name for sensitive in sensitive_names):
                return True
        
        return False

    def _check_password_inputs(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Check for password inputs in non-secure context.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of password input issues
        """
        password_inputs = []
        
        # Find all password inputs
        inputs = soup.find_all("input", type="password")
        
        for input_tag in inputs:
            form = input_tag.find_parent("form")
            
            if form:
                action = form.get("action", "")
                method = form.get("method", "get").lower()
                
                password_inputs.append({
                    "form_action": action or "(current page)",
                    "form_method": method,
                    "input_name": input_tag.get("name", "(unnamed)"),
                })
            else:
                password_inputs.append({
                    "form_action": "(no form)",
                    "form_method": "(no form)",
                    "input_name": input_tag.get("name", "(unnamed)"),
                })
        
        return password_inputs

    def _check_sensitive_files(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Check for links to sensitive files.

        Args:
            soup: BeautifulSoup object
            base_url: Base URL of the page

        Returns:
            List of sensitive file URLs
        """
        sensitive_files = []
        
        # Extract all URLs from the page
        urls = extract_urls_from_html(str(soup), base_url)
        
        # Define patterns for sensitive files
        sensitive_patterns = [
            r"\.git/",
            r"\.svn/",
            r"\.env",
            r"\.config",
            r"config\.php",
            r"config\.js",
            r"config\.xml",
            r"config\.json",
            r"settings\.php",
            r"settings\.js",
            r"settings\.xml",
            r"settings\.json",
            r"database\.php",
            r"db\.php",
            r"backup",
            r"\.bak$",
            r"\.old$",
            r"\.backup$",
            r"\.zip$",
            r"\.tar$",
            r"\.tar\.gz$",
            r"\.sql$",
            r"\.log$",
            r"phpinfo\.php$",
            r"test\.php$",
            r"admin",
            r"administrator",
            r"wp-admin",
            r"wp-config\.php",
            r"\.htaccess$",
            r"\.htpasswd$",
            r"web\.config$",
        ]
        
        # Check each URL against sensitive patterns
        for url in urls:
            for pattern in sensitive_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    sensitive_files.append(url)
                    break
        
        return sensitive_files

    def _check_error_messages(self, soup: BeautifulSoup, html_content: str) -> List[Dict[str, str]]:
        """Check for error messages that might reveal sensitive information.

        Args:
            soup: BeautifulSoup object
            html_content: Raw HTML content

        Returns:
            List of error message issues
        """
        error_messages = []
        
        # Define patterns for error messages
        error_patterns = [
            (r"sql syntax.*?mysql", "SQL Error"),
            (r"Warning.*?\\[mysql_", "SQL Error"),
            (r"PostgreSQL.*?ERROR", "SQL Error"),
            (r"Driver.*? SQL[-_ ]*Server", "SQL Error"),
            (r"ORA-[0-9][0-9][0-9][0-9]", "Oracle Error"),
            (r"Microsoft OLE DB Provider for SQL Server", "SQL Error"),
            (r"Uncaught exception", "Application Error"),
            (r"Traceback \(most recent call last\)", "Application Error"),
            (r"syntax error at line", "Application Error"),
            (r"Error Occurred While Processing Request", "Application Error"),
            (r"Server Error in.*?Application", "Application Error"),
            (r"Fatal error:", "PHP Error"),
            (r"Warning:", "PHP Warning"),
            (r"Parse error:", "PHP Error"),
            (r"Notice:", "PHP Notice"),
            (r"Undefined index:", "PHP Notice"),
            (r"exception '[^']*?' with message", "Application Error"),
            (r"<b>Warning</b>:", "PHP Warning"),
            (r"<b>Fatal error</b>:", "PHP Error"),
            (r"<b>Notice</b>:", "PHP Notice"),
        ]
        
        # Check for error patterns in HTML content
        for pattern, error_type in error_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                # Get some context around the match
                start = max(0, html_content.lower().find(match.lower()) - 50)
                end = min(len(html_content), html_content.lower().find(match.lower()) + len(match) + 50)
                context = html_content[start:end]
                
                error_messages.append({
                    "type": error_type,
                    "message": match,
                    "context": context,
                })
        
        return error_messages

    def _create_sensitive_comments_vulnerability(
        self, url: HttpUrl, comment_issues: List[Dict[str, str]]
    ) -> Vulnerability:
        """Create a vulnerability for sensitive information in HTML comments.

        Args:
            url: Target URL
            comment_issues: List of comment issues

        Returns:
            Vulnerability object
        """
        # Determine severity based on the types of issues
        severity = Severity.LOW
        for issue in comment_issues:
            if issue["type"] in ["Password", "API Key", "Secret", "Token"]:
                severity = Severity.MEDIUM
                break
        
        # Create evidence
        evidence = Evidence(
            type="html_comments",
            data=comment_issues,
            description=f"Found {len(comment_issues)} potentially sensitive HTML comments",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Sensitive Information in HTML Comments",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=severity,
            confidence=Confidence.MEDIUM,
            description=f"The page contains {len(comment_issues)} HTML comments that may reveal sensitive information such as credentials, internal paths, or developer notes.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Remove all sensitive information from HTML comments in production code. Consider implementing a process to strip comments from production builds.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cwe.mitre.org/data/definitions/615.html",
            ],
            cwe=615,  # CWE-615: Information Exposure Through Comments
            tags={"information-disclosure", "html-comments"},
        )

    def _create_mixed_content_vulnerability(
        self, url: HttpUrl, mixed_content: List[Dict[str, str]]
    ) -> Vulnerability:
        """Create a vulnerability for mixed content.

        Args:
            url: Target URL
            mixed_content: List of mixed content issues

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="mixed_content",
            data=mixed_content,
            description=f"Found {len(mixed_content)} instances of mixed content",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Mixed Content",
            type=VulnerabilityType.CRYPTOGRAPHIC_FAILURES,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description=f"The page loads {len(mixed_content)} resources over HTTP despite being served over HTTPS. This mixed content can be intercepted and modified by attackers, compromising the security of the entire page.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Ensure all resources are loaded over HTTPS. Update all references to use relative URLs or explicitly use HTTPS.",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            cwe=311,  # CWE-311: Missing Encryption of Sensitive Data
            tags={"mixed-content", "tls"},
        )

    def _create_insecure_forms_vulnerability(
        self, url: HttpUrl, insecure_forms: List[Dict[str, str]]
    ) -> Vulnerability:
        """Create a vulnerability for insecure forms.

        Args:
            url: Target URL
            insecure_forms: List of insecure form issues

        Returns:
            Vulnerability object
        """
        # Determine severity based on the types of issues
        severity = Severity.MEDIUM
        for form in insecure_forms:
            if "Form submits to HTTP URL" in form["issues"]:
                severity = Severity.HIGH
                break
        
        # Create evidence
        evidence = Evidence(
            type="insecure_forms",
            data=insecure_forms,
            description=f"Found {len(insecure_forms)} insecure forms",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Insecure Forms",
            type=VulnerabilityType.CRYPTOGRAPHIC_FAILURES,
            severity=severity,
            confidence=Confidence.HIGH,
            description=f"The page contains {len(insecure_forms)} forms with security issues that could lead to sensitive data exposure or other security vulnerabilities.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Ensure all forms use HTTPS for submission, use POST method for sensitive data, and include appropriate security attributes.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            cwe=319,  # CWE-319: Cleartext Transmission of Sensitive Information
            tags={"forms", "sensitive-data"},
        )

    def _create_password_over_http_vulnerability(
        self, url: HttpUrl, password_inputs: List[Dict[str, str]]
    ) -> Vulnerability:
        """Create a vulnerability for password inputs over HTTP.

        Args:
            url: Target URL
            password_inputs: List of password input issues

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="password_inputs",
            data=password_inputs,
            description=f"Found {len(password_inputs)} password inputs on non-HTTPS page",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Password Input Over HTTP",
            type=VulnerabilityType.CRYPTOGRAPHIC_FAILURES,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=f"The page contains {len(password_inputs)} password input fields but is served over HTTP. Passwords submitted through these fields can be intercepted by attackers.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Serve all pages with password inputs over HTTPS. Redirect HTTP requests to HTTPS for these pages.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
            ],
            cwe=319,  # CWE-319: Cleartext Transmission of Sensitive Information
            tags={"password", "http", "sensitive-data"},
        )

    def _create_sensitive_files_vulnerability(
        self, url: HttpUrl, sensitive_links: List[str]
    ) -> Vulnerability:
        """Create a vulnerability for sensitive file links.

        Args:
            url: Target URL
            sensitive_links: List of sensitive file URLs

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="sensitive_files",
            data=sensitive_links,
            description=f"Found {len(sensitive_links)} links to potentially sensitive files",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Sensitive File Exposure",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description=f"The page contains {len(sensitive_links)} links to potentially sensitive files that may expose configuration details, backup data, or administrative interfaces.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Restrict access to sensitive files and directories. Remove links to these resources from public pages.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information",
                "https://cwe.mitre.org/data/definitions/538.html",
            ],
            cwe=538,  # CWE-538: File and Directory Information Exposure
            tags={"sensitive-files", "information-disclosure"},
        )

    def _create_error_messages_vulnerability(
        self, url: HttpUrl, error_messages: List[Dict[str, str]]
    ) -> Vulnerability:
        """Create a vulnerability for error messages.

        Args:
            url: Target URL
            error_messages: List of error message issues

        Returns:
            Vulnerability object
        """
        # Determine severity based on the types of issues
        severity = Severity.LOW
        for error in error_messages:
            if error["type"] in ["SQL Error", "Application Error"]:
                severity = Severity.MEDIUM
                break
        
        # Create evidence
        evidence = Evidence(
            type="error_messages",
            data=error_messages,
            description=f"Found {len(error_messages)} error messages",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Verbose Error Messages",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=severity,
            confidence=Confidence.MEDIUM,
            description=f"The page contains {len(error_messages)} error messages that may reveal sensitive information about the application's internal workings, such as database structure, file paths, or code snippets.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Configure the application to display generic error messages to users and log detailed errors server-side. Implement proper exception handling.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
                "https://cwe.mitre.org/data/definitions/209.html",
            ],
            cwe=209,  # CWE-209: Information Exposure Through an Error Message
            tags={"error-messages", "information-disclosure"},
        )
