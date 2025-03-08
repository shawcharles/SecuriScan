"""
Cross-Site Scripting (XSS) Scanner Module.

This module tests for XSS vulnerabilities in web applications.
"""

import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from securiscan.core.exceptions import ScanError
from securiscan.core.result import (
    Confidence,
    Evidence,
    ScanTarget,
    Severity,
    Vulnerability,
    VulnerabilityType,
)
from securiscan.core.scanner import BaseScanner
from securiscan.utils.http import extract_form_data


class XSSScanner(BaseScanner):
    """Scanner for detecting Cross-Site Scripting (XSS) vulnerabilities."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the XSS scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Testing for XSS vulnerabilities on {target.url}")
        vulnerabilities = []

        try:
            # Send request to the target
            response = self.scanner.send_request(target.url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Extract forms
            forms = self._extract_forms(soup)
            
            # Test each form for XSS vulnerabilities
            for form in forms:
                xss_results = self._test_form_for_xss(target.url, form)
                vulnerabilities.extend(xss_results)
            
            # Test URL parameters for XSS vulnerabilities
            if target.url.query:
                url_xss_results = self._test_url_parameters_for_xss(target.url)
                vulnerabilities.extend(url_xss_results)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error testing for XSS vulnerabilities: {str(e)}", exc_info=True)
            return []

    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract forms from HTML.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of forms
        """
        forms = []
        
        for form in soup.find_all("form"):
            form_data = {
                "action": form.get("action", ""),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }
            
            # Extract inputs
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.get("type", "text").lower()
                input_name = input_tag.get("name", "")
                
                # Skip submit buttons and hidden fields
                if input_type in ["submit", "button", "image", "reset"] or not input_name:
                    continue
                
                form_data["inputs"].append({
                    "name": input_name,
                    "type": input_type,
                })
            
            forms.append(form_data)
        
        return forms

    def _test_form_for_xss(self, url: HttpUrl, form: Dict) -> List[Vulnerability]:
        """Test a form for XSS vulnerabilities.

        Args:
            url: Target URL
            form: Form data

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x:x onerror=alert('XSS')>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<div style=\"width: expression(alert('XSS'))\">",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<object data=\"javascript:alert('XSS')\"></object>",
            "<svg><script>alert('XSS')</script></svg>",
        ]
        
        # Determine form action URL
        action_url = form["action"]
        if not action_url:
            action_url = str(url)
        elif not action_url.startswith(("http://", "https://")):
            # Relative URL
            base_url = str(url).split("?")[0]
            if action_url.startswith("/"):
                # Absolute path
                parts = str(url).split("/")
                base_url = f"{parts[0]}//{parts[2]}"
            action_url = f"{base_url.rstrip('/')}/{action_url.lstrip('/')}"
        
        # Test each input with each payload
        for input_field in form["inputs"]:
            for payload in xss_payloads:
                # Prepare form data
                form_data = {}
                for field in form["inputs"]:
                    if field["name"] == input_field["name"]:
                        form_data[field["name"]] = payload
                    else:
                        # Use dummy values for other fields
                        if field["type"] == "email":
                            form_data[field["name"]] = "test@example.com"
                        elif field["type"] == "number":
                            form_data[field["name"]] = "123"
                        else:
                            form_data[field["name"]] = "test"
                
                try:
                    # Send request
                    if form["method"] == "post":
                        response = self.scanner.session.post(action_url, data=form_data, timeout=self.scanner.config.timeout)
                    else:
                        response = self.scanner.session.get(action_url, params=form_data, timeout=self.scanner.config.timeout)
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        # Check if the payload is properly encoded/escaped
                        if self._is_payload_executable(response.text, payload):
                            vuln = self._create_xss_vulnerability(
                                url=url,
                                payload=payload,
                                param=input_field["name"],
                                form_action=action_url,
                                form_method=form["method"],
                                is_form=True,
                            )
                            vulnerabilities.append(vuln)
                            
                            # No need to test more payloads for this input
                            break
                
                except Exception as e:
                    self.logger.warning(f"Error testing form input {input_field['name']} for XSS: {str(e)}")
        
        return vulnerabilities

    def _test_url_parameters_for_xss(self, url: HttpUrl) -> List[Vulnerability]:
        """Test URL parameters for XSS vulnerabilities.

        Args:
            url: Target URL

        Returns:
            List of vulnerabilities found
        """
        vulnerabilities = []
        
        # XSS payloads to test
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
        ]
        
        # Parse query parameters
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
        
        parsed_url = urlparse(str(url))
        query_params = parse_qs(parsed_url.query)
        
        # Test each parameter with each payload
        for param, values in query_params.items():
            for payload in xss_payloads:
                # Create a copy of the query parameters
                new_params = {k: v for k, v in query_params.items()}
                new_params[param] = [payload]
                
                # Build the new URL
                new_query = urlencode(new_params, doseq=True)
                new_url_parts = list(parsed_url)
                new_url_parts[4] = new_query
                new_url = urlunparse(new_url_parts)
                
                try:
                    # Send request
                    response = self.scanner.session.get(new_url, timeout=self.scanner.config.timeout)
                    
                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        # Check if the payload is properly encoded/escaped
                        if self._is_payload_executable(response.text, payload):
                            vuln = self._create_xss_vulnerability(
                                url=url,
                                payload=payload,
                                param=param,
                                form_action=None,
                                form_method=None,
                                is_form=False,
                            )
                            vulnerabilities.append(vuln)
                            
                            # No need to test more payloads for this parameter
                            break
                
                except Exception as e:
                    self.logger.warning(f"Error testing URL parameter {param} for XSS: {str(e)}")
        
        return vulnerabilities

    def _is_payload_executable(self, html: str, payload: str) -> bool:
        """Check if a payload is executable in the HTML context.

        Args:
            html: HTML content
            payload: XSS payload

        Returns:
            True if the payload is executable, False otherwise
        """
        # This is a simplified check and would need to be more sophisticated in a real implementation
        
        # Check if the payload is inside a script tag
        script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL)
        for script in script_pattern.findall(html):
            if payload in script:
                return True
        
        # Check if the payload is inside an event handler
        event_pattern = re.compile(r"on\w+\s*=\s*['\"].*?" + re.escape(payload) + r".*?['\"]", re.IGNORECASE)
        if event_pattern.search(html):
            return True
        
        # Check if the payload is inside a javascript: URL
        js_url_pattern = re.compile(r"javascript:.*?" + re.escape(payload), re.IGNORECASE)
        if js_url_pattern.search(html):
            return True
        
        # Check if the payload is inside a style attribute with expression
        style_pattern = re.compile(r"style\s*=\s*['\"].*?expression\s*\(.*?" + re.escape(payload) + r".*?\)['\"]", re.IGNORECASE)
        if style_pattern.search(html):
            return True
        
        # Check if the payload contains script tags and is not inside a textarea, pre, or other safe elements
        if "<script" in payload:
            # Check if the payload is not inside a textarea or pre tag
            textarea_pattern = re.compile(r"<textarea[^>]*>.*?" + re.escape(payload) + r".*?</textarea>", re.IGNORECASE | re.DOTALL)
            pre_pattern = re.compile(r"<pre[^>]*>.*?" + re.escape(payload) + r".*?</pre>", re.IGNORECASE | re.DOTALL)
            
            if not textarea_pattern.search(html) and not pre_pattern.search(html):
                # Check if the script tag is properly closed
                if "</script>" in payload:
                    return True
        
        return False

    def _create_xss_vulnerability(
        self,
        url: HttpUrl,
        payload: str,
        param: str,
        form_action: Optional[str],
        form_method: Optional[str],
        is_form: bool,
    ) -> Vulnerability:
        """Create a vulnerability for XSS.

        Args:
            url: Target URL
            payload: XSS payload
            param: Parameter name
            form_action: Form action URL
            form_method: Form method
            is_form: Whether the vulnerability is in a form

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence_data = {
            "payload": payload,
            "param": param,
            "is_form": is_form,
        }
        
        if is_form:
            evidence_data["form_action"] = form_action
            evidence_data["form_method"] = form_method
        
        evidence = Evidence(
            type="xss",
            data=evidence_data,
            description=f"XSS vulnerability found in {'form field' if is_form else 'URL parameter'} '{param}'",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Cross-Site Scripting (XSS)",
            type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=f"A Cross-Site Scripting (XSS) vulnerability was found in the {'form field' if is_form else 'URL parameter'} '{param}'. This vulnerability allows attackers to inject malicious scripts that can steal cookies, session tokens, or other sensitive information.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Implement proper input validation and output encoding. Use a Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities.",
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting",
            ],
            cwe=79,  # CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
            tags={"xss", "injection", "client-side"},
        )
