#!/usr/bin/env python3
# Website Security Assessment Script
# This script performs legitimate, non-invasive security assessment of a website
# For educational and authorized testing purposes only

import requests
import socket
import ssl
import json
import re
import time
import pandas as pd
import matplotlib.pyplot as plt
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WebsiteSecurityAssessment:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        self.domain = self.parsed_url.netloc
        self.results = {
            "reconnaissance": {},
            "headers": {},
            "content": {},
            "ssl_tls": {},
            "tech_stack": {},
            "directories": {},
            "summary": {}
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
        })
        self.visited_urls = set()
        self.forms = []
        self.links = []
        self.issues = []
        
    def run_assessment(self):
        """Run the complete security assessment"""
        print(f"Starting security assessment of {self.target_url}")
        
        # Run all assessment modules
        self.perform_reconnaissance()
        self.analyze_headers()
        self.analyze_content()
        self.assess_ssl_tls()
        self.detect_tech_stack()
        self.analyze_directories()
        
        # Generate summary
        self.generate_summary()
        
        print("Assessment complete!")
        return self.results
    
    def perform_reconnaissance(self):
        """Perform initial reconnaissance"""
        print("\n[+] Performing initial reconnaissance...")
        
        # Get server IP
        try:
            ip = socket.gethostbyname(self.domain)
            self.results["reconnaissance"]["server_ip"] = ip
            print(f"Server IP: {ip}")
        except socket.gaierror:
            self.results["reconnaissance"]["server_ip"] = "Unable to resolve"
            print("Unable to resolve domain to IP")
        
        # Check robots.txt
        try:
            robots_url = f"{self.base_url}/robots.txt"
            response = self.session.get(robots_url, timeout=10)
            if response.status_code == 200:
                self.results["reconnaissance"]["robots_txt"] = {
                    "exists": True,
                    "content": response.text[:500] + ("..." if len(response.text) > 500 else "")
                }
                print("robots.txt found")
                
                # Check for disallowed directories
                disallowed = re.findall(r'Disallow: (.*)', response.text)
                self.results["reconnaissance"]["disallowed_paths"] = disallowed
                if disallowed:
                    print(f"Found {len(disallowed)} disallowed paths")
                    self.add_issue("Information Disclosure", "Medium", 
                                  f"robots.txt reveals {len(disallowed)} restricted paths",
                                  "Consider reviewing robots.txt to ensure it doesn't reveal sensitive directories")
            else:
                self.results["reconnaissance"]["robots_txt"] = {"exists": False}
                print("No robots.txt found")
        except requests.RequestException as e:
            self.results["reconnaissance"]["robots_txt"] = {"exists": "error", "error": str(e)}
            print(f"Error checking robots.txt: {e}")
        
        # Check sitemap.xml
        try:
            sitemap_url = f"{self.base_url}/sitemap.xml"
            response = self.session.get(sitemap_url, timeout=10)
            if response.status_code == 200:
                self.results["reconnaissance"]["sitemap_xml"] = {
                    "exists": True,
                    "content_length": len(response.text)
                }
                print("sitemap.xml found")
                
                # Parse sitemap for URLs
                soup = BeautifulSoup(response.text, 'html.parser')
                urls = [loc.text for loc in soup.find_all('loc')]
                self.results["reconnaissance"]["sitemap_urls_count"] = len(urls)
                print(f"Found {len(urls)} URLs in sitemap")
            else:
                self.results["reconnaissance"]["sitemap_xml"] = {"exists": False}
                print("No sitemap.xml found")
        except requests.RequestException as e:
            self.results["reconnaissance"]["sitemap_xml"] = {"exists": "error", "error": str(e)}
            print(f"Error checking sitemap.xml: {e}")
            
        # Check for common security files
        security_files = [
            "security.txt", 
            ".well-known/security.txt"
        ]
        
        for file in security_files:
            try:
                file_url = f"{self.base_url}/{file}"
                response = self.session.get(file_url, timeout=10)
                if response.status_code == 200:
                    self.results["reconnaissance"][f"{file.replace('/', '_')}"] = {
                        "exists": True,
                        "content": response.text[:500] + ("..." if len(response.text) > 500 else "")
                    }
                    print(f"{file} found")
                else:
                    self.results["reconnaissance"][f"{file.replace('/', '_')}"] = {"exists": False}
            except requests.RequestException:
                self.results["reconnaissance"][f"{file.replace('/', '_')}"] = {"exists": "error"}
    
    def analyze_headers(self):
        """Analyze HTTP headers for security issues"""
        print("\n[+] Analyzing HTTP headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Store all headers
            self.results["headers"]["all_headers"] = dict(headers)
            print(f"Collected {len(headers)} HTTP headers")
            
            # Check for security headers
            security_headers = {
                "Strict-Transport-Security": {
                    "present": "Strict-Transport-Security" in headers,
                    "value": headers.get("Strict-Transport-Security", "")
                },
                "Content-Security-Policy": {
                    "present": "Content-Security-Policy" in headers,
                    "value": headers.get("Content-Security-Policy", "")
                },
                "X-Frame-Options": {
                    "present": "X-Frame-Options" in headers,
                    "value": headers.get("X-Frame-Options", "")
                },
                "X-Content-Type-Options": {
                    "present": "X-Content-Type-Options" in headers,
                    "value": headers.get("X-Content-Type-Options", "")
                },
                "Referrer-Policy": {
                    "present": "Referrer-Policy" in headers,
                    "value": headers.get("Referrer-Policy", "")
                },
                "Permissions-Policy": {
                    "present": "Permissions-Policy" in headers,
                    "value": headers.get("Permissions-Policy", "")
                },
                "X-XSS-Protection": {
                    "present": "X-XSS-Protection" in headers,
                    "value": headers.get("X-XSS-Protection", "")
                }
            }
            
            self.results["headers"]["security_headers"] = security_headers
            
            # Check for missing security headers
            missing_headers = [header for header, data in security_headers.items() if not data["present"]]
            self.results["headers"]["missing_security_headers"] = missing_headers
            
            if missing_headers:
                print(f"Missing security headers: {', '.join(missing_headers)}")
                self.add_issue("Missing Security Headers", "Medium", 
                              f"Missing {len(missing_headers)} security headers: {', '.join(missing_headers)}",
                              "Implement the missing security headers to improve website security")
            
            # Check for information disclosure in headers
            sensitive_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
            disclosed_info = {header: headers[header] for header in sensitive_headers if header in headers}
            
            self.results["headers"]["information_disclosure"] = disclosed_info
            
            if disclosed_info:
                print(f"Information disclosure in headers: {json.dumps(disclosed_info)}")
                self.add_issue("Information Disclosure", "Low", 
                              f"Server information disclosed in headers: {json.dumps(disclosed_info)}",
                              "Remove or obfuscate headers that reveal server technologies")
            
            # Check cookie security
            if "Set-Cookie" in headers:
                cookies = response.cookies
                insecure_cookies = []
                
                for cookie in cookies:
                    cookie_info = {
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "httponly": cookie.has_nonstandard_attr("httponly") or cookie.has_nonstandard_attr("HttpOnly"),
                        "samesite": cookie.get_nonstandard_attr("samesite", None)
                    }
                    
                    if not cookie.secure or not cookie_info["httponly"]:
                        insecure_cookies.append(cookie_info)
                
                self.results["headers"]["cookies"] = {
                    "count": len(cookies),
                    "insecure_count": len(insecure_cookies),
                    "insecure_cookies": insecure_cookies
                }
                
                if insecure_cookies:
                    print(f"Found {len(insecure_cookies)} insecure cookies")
                    self.add_issue("Insecure Cookies", "Medium", 
                                  f"{len(insecure_cookies)} cookies missing Secure or HttpOnly flags",
                                  "Set Secure and HttpOnly flags on all cookies")
            else:
                self.results["headers"]["cookies"] = {"count": 0}
                
        except requests.RequestException as e:
            self.results["headers"]["error"] = str(e)
            print(f"Error analyzing headers: {e}")
    
    def analyze_content(self):
        """Analyze page content for security issues"""
        print("\n[+] Analyzing page content...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract meta information
            meta_tags = soup.find_all('meta')
            meta_info = {}
            
            for tag in meta_tags:
                name = tag.get('name') or tag.get('property')
                if name:
                    content = tag.get('content')
                    meta_info[name] = content
            
            self.results["content"]["meta_tags"] = meta_info
            print(f"Found {len(meta_tags)} meta tags")
            
            # Check for forms
            forms = soup.find_all('form')
            form_details = []
            
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                
                inputs = []
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', '')
                    input_name = input_tag.get('name', '')
                    inputs.append({"type": input_type, "name": input_name})
                
                form_info = {
                    "action": action,
                    "method": method,
                    "inputs": inputs
                }
                
                form_details.append(form_info)
                
                # Check for insecure form submission
                if method == "post" and not self.target_url.startswith("https://"):
                    self.add_issue("Insecure Form Submission", "High", 
                                  f"Form submits data using POST over HTTP",
                                  "Use HTTPS for all form submissions")
            
            self.results["content"]["forms"] = form_details
            print(f"Found {len(forms)} forms")
            
            # Extract links
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag.get('href')
                if href and not href.startswith('#') and not href.startswith('javascript:'):
                    if not href.startswith('http'):
                        href = urljoin(self.base_url, href)
                    links.append(href)
            
            self.results["content"]["links"] = {
                "count": len(links),
                "external_links": [link for link in links if not link.startswith(self.base_url)]
            }
            print(f"Found {len(links)} links")
            
            # Check for mixed content
            if self.target_url.startswith("https://"):
                mixed_content = []
                
                for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
                    src = tag.get('src') or tag.get('href')
                    if src and src.startswith('http://'):
                        mixed_content.append({
                            "type": tag.name,
                            "url": src
                        })
                
                self.results["content"]["mixed_content"] = mixed_content
                
                if mixed_content:
                    print(f"Found {len(mixed_content)} mixed content issues")
                    self.add_issue("Mixed Content", "Medium", 
                                  f"{len(mixed_content)} resources loaded over HTTP on HTTPS page",
                                  "Ensure all resources are loaded over HTTPS")
            
            # Check for comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            
            if comments:
                self.results["content"]["comments"] = {
                    "count": len(comments),
                    "samples": [comment.strip()[:100] + "..." for comment in comments[:5]]
                }
                print(f"Found {len(comments)} HTML comments")
                
                # Look for potentially sensitive information in comments
                sensitive_patterns = [
                    r'password', r'user', r'key', r'api', r'secret', r'token', r'auth', 
                    r'todo', r'fix', r'bug', r'issue', r'hack'
                ]
                
                sensitive_comments = []
                for comment in comments:
                    for pattern in sensitive_patterns:
                        if re.search(pattern, comment, re.IGNORECASE):
                            sensitive_comments.append(comment.strip()[:100] + "...")
                            break
                
                if sensitive_comments:
                    self.results["content"]["sensitive_comments"] = sensitive_comments
                    print(f"Found {len(sensitive_comments)} potentially sensitive comments")
                    self.add_issue("Information Disclosure", "Medium", 
                                  f"{len(sensitive_comments)} potentially sensitive HTML comments found",
                                  "Remove comments containing sensitive information from production code")
            
        except requests.RequestException as e:
            self.results["content"]["error"] = str(e)
            print(f"Error analyzing content: {e}")
    
    def assess_ssl_tls(self):
        """Assess SSL/TLS configuration"""
        print("\n[+] Assessing SSL/TLS configuration...")
        
        if not self.target_url.startswith("https://"):
            self.results["ssl_tls"]["enabled"] = False
            print("Website does not use HTTPS")
            self.add_issue("No HTTPS", "High", 
                          "Website does not use HTTPS encryption",
                          "Implement HTTPS across the entire website")
            return
        
        self.results["ssl_tls"]["enabled"] = True
        
        try:
            hostname = self.parsed_url.netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = cert['notAfter']
                    not_before = cert['notBefore']
                    
                    # Parse dates
                    from datetime import datetime
                    date_format = r'%b %d %H:%M:%S %Y %Z'
                    expiry_date = datetime.strptime(not_after, date_format)
                    start_date = datetime.strptime(not_before, date_format)
                    current_date = datetime.now()
                    
                    days_to_expiry = (expiry_date - current_date).days
                    
                    self.results["ssl_tls"]["certificate"] = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "version": cert['version'],
                        "notBefore": not_before,
                        "notAfter": not_after,
                        "daysToExpiry": days_to_expiry,
                        "subjectAltName": cert.get('subjectAltName', [])
                    }
                    
                    print(f"SSL certificate expires in {days_to_expiry} days")
                    
                    if days_to_expiry < 30:
                        self.add_issue("Certificate Expiring Soon", "Medium", 
                                      f"SSL certificate expires in {days_to_expiry} days",
                                      "Renew SSL certificate before expiration")
                    
                    # Get cipher and protocol information
                    cipher = ssock.cipher()
                    self.results["ssl_tls"]["cipher"] = {
                        "name": cipher[0],
                        "version": cipher[1],
                        "bits": cipher[2]
                    }
                    
                    protocol_version = ssock.version()
                    self.results["ssl_tls"]["protocol"] = protocol_version
                    
                    # Check for weak protocols
                    if protocol_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        self.add_issue("Weak SSL/TLS Protocol", "High", 
                                      f"Website uses outdated protocol: {protocol_version}",
                                      "Upgrade to TLSv1.2 or TLSv1.3")
                    
                    print(f"SSL/TLS Protocol: {protocol_version}, Cipher: {cipher[0]}")
                    
        except (socket.gaierror, socket.error, ssl.SSLError, ssl.CertificateError) as e:
            self.results["ssl_tls"]["error"] = str(e)
            print(f"Error assessing SSL/TLS: {e}")
            self.add_issue("SSL/TLS Error", "High", 
                          f"Error with SSL/TLS configuration: {str(e)}",
                          "Review and fix SSL/TLS configuration")
    
    def detect_tech_stack(self):
        """Detect technology stack used by the website"""
        print("\n[+] Detecting technology stack...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = {
                "server": response.headers.get("Server", "Unknown"),
                "programming_languages": [],
                "frameworks": [],
                "cms": "Unknown",
                "javascript_libraries": [],
                "analytics": [],
                "third_party_services": []
            }
            
            # Check for common CMS indicators
            cms_patterns = {
                "WordPress": [
                    r'wp-content', r'wp-includes', r'wp-json', 
                    r'wordpress', r'wp-'
                ],
                "Joomla": [
                    r'joomla', r'com_content', r'com_users'
                ],
                "Drupal": [
                    r'drupal', r'sites/all', r'sites/default'
                ],
                "Magento": [
                    r'magento', r'skin/frontend', r'Mage.Cookies'
                ],
                "Shopify": [
                    r'shopify', r'cdn.shopify.com'
                ],
                "Wix": [
                    r'wix.com', r'wixsite.com', r'_wix'
                ],
                "Squarespace": [
                    r'squarespace', r'static1.squarespace.com'
                ]
            }
            
            html_content = response.text
            
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        technologies["cms"] = cms
                        break
                if technologies["cms"] != "Unknown":
                    break
            
            # Check for JavaScript libraries
            js_libraries = {
                "jQuery": [r'jquery', r'jQuery'],
                "React": [r'react', r'reactjs', r'React.createElement'],
                "Angular": [r'angular', r'ng-app', r'ng-controller'],
                "Vue.js": [r'vue', r'Vue', r'v-bind', r'v-on'],
                "Bootstrap": [r'bootstrap', r'navbar-toggler'],
                "Lodash": [r'lodash', r'_\.(map|filter|find)'],
                "Moment.js": [r'moment', r'moment.js'],
                "D3.js": [r'd3', r'D3.js'],
                "GSAP": [r'gsap', r'TweenMax'],
                "Modernizr": [r'modernizr', r'Modernizr']
            }
            
            for library, patterns in js_libraries.items():
                for pattern in patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        technologies["javascript_libraries"].append(library)
                        break
            
            # Check for analytics and tracking
            analytics_services = {
                "Google Analytics": [r'google-analytics.com', r'ga\(', r'gtag'],
                "Google Tag Manager": [r'googletagmanager.com', r'gtm.js'],
                "Facebook Pixel": [r'connect.facebook.net', r'fbq\('],
                "Hotjar": [r'hotjar', r'hjSetting'],
                "Matomo/Piwik": [r'matomo', r'piwik'],
                "Mixpanel": [r'mixpanel'],
                "Segment": [r'segment.com', r'analytics.js']
            }
            
            for service, patterns in analytics_services.items():
                for pattern in patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        technologies["analytics"].append(service)
                        break
            
            # Check for third-party services
            third_party_services = {
                "Cloudflare": [r'cloudflare', r'__cf'],
                "AWS": [r'amazonaws.com', r'aws-'],
                "Akamai": [r'akamai', r'akam'],
                "Stripe": [r'stripe.com', r'Stripe.'],
                "PayPal": [r'paypal.com', r'paypal'],
                "Disqus": [r'disqus.com', r'disqus'],
                "Intercom": [r'intercom', r'intercomSettings'],
                "Zendesk": [r'zendesk', r'zdassets'],
                "Hubspot": [r'hubspot', r'hs-script'],
                "Mailchimp": [r'mailchimp', r'mc.js']
            }
            
            for service, patterns in third_party_services.items():
                for pattern in patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        technologies["third_party_services"].append(service)
                        break
            
            # Check for programming languages/frameworks
            frameworks = {
                "PHP": [r'\.php', r'php'],
                "ASP.NET": [r'\.aspx', r'__VIEWSTATE', r'asp.net'],
                "Ruby on Rails": [r'rails', r'ruby'],
                "Django": [r'django', r'csrftoken'],
                "Laravel": [r'laravel', r'csrf-token'],
                "Express.js": [r'express', r'node_modules'],
                "Flask": [r'flask'],
                "Spring": [r'spring', r'java']
            }
            
            for framework, patterns in frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        technologies["frameworks"].append(framework)
                        break
            
            self.results["tech_stack"] = technologies
            
            print(f"CMS: {technologies['cms']}")
            print(f"JavaScript Libraries: {', '.join(technologies['javascript_libraries'])}")
            print(f"Analytics: {', '.join(technologies['analytics'])}")
            print(f"Third-party Services: {', '.join(technologies['third_party_services'])}")
            
            # Check for outdated libraries (this would require a database of versions)
            # For now, just note that we found libraries that could potentially be outdated
            if technologies["javascript_libraries"]:
                self.add_issue("Potential Outdated Libraries", "Medium", 
                              f"Website uses JavaScript libraries that may be outdated",
                              "Regularly update all JavaScript libraries to their latest versions")
            
        except requests.RequestException as e:
            self.results["tech_stack"]["error"] = str(e)
            print(f"Error detecting technology stack: {e}")
    
    def analyze_directories(self):
        """Check for common directories and files"""
        print("\n[+] Analyzing directories and files...")
        
        common_paths = [
            "admin", "administrator", "login", "wp-admin", "cpanel", "phpmyadmin",
            "config", "backup", "backups", "data", "db", "database",
            "wp-content/uploads", "wp-content/backup", "images", "img", "css", "js",
            ".git", ".env", ".htaccess", "web.config", "crossdomain.xml",
            "README.md", "CHANGELOG.md", "LICENSE", "package.json", "composer.json"
        ]
        
        found_paths = []
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            def check_path(path):
                url = f"{self.base_url}/{path}"
                try:
                    response = self.session.head(url, timeout=5, allow_redirects=False)
                    if response.status_code < 400:  # Consider all non-error codes as "found"
                        return {
                            "path": path,
                            "url": url,
                            "status_code": response.status_code
                        }
                except requests.RequestException:
                    pass
                return None
            
            results = list(executor.map(check_path, common_paths))
            found_paths = [result for result in results if result is not None]
        
        self.results["directories"]["found_paths"] = found_paths
        
        if found_paths:
            print(f"Found {len(found_paths)} accessible paths")
            
            sensitive_paths = [p for p in found_paths if any(s in p["path"] for s in 
                                                           ["admin", "config", "backup", "db", ".git", ".env"])]
            
            if sensitive_paths:
                self.add_issue("Sensitive Directories Exposed", "High", 
                              f"{len(sensitive_paths)} potentially sensitive directories/files are accessible",
                              "Restrict access to sensitive directories and files")
                print(f"Found {len(sensitive_paths)} potentially sensitive directories/files")
        else:
            print("No common directories/files found")
    
    def add_issue(self, title, severity, description, recommendation):
        """Add an issue to the issues list"""
        self.issues.append({
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation
        })
    
    def generate_summary(self):
        """Generate a summary of findings"""
        print("\n[+] Generating summary...")
        
        # Count issues by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for issue in self.issues:
            severity_counts[issue["severity"]] += 1
        
        self.results["summary"]["issues_count"] = len(self.issues)
        self.results["summary"]["severity_counts"] = severity_counts
        self.results["summary"]["issues"] = self.issues
        
        # Calculate overall risk score (simple algorithm)
        risk_score = (severity_counts["High"] * 10 + 
                      severity_counts["Medium"] * 5 + 
                      severity_counts["Low"] * 2)
        
        # Normalize to 0-100 scale (assuming max 10 issues per severity)
        max_possible_score = 10 * 10 + 10 * 5 + 10 * 2
        normalized_score = min(100, (risk_score / max_possible_score) * 100)
        
        self.results["summary"]["risk_score"] = normalized_score
        
        # Determine risk level
        if normalized_score >= 75:
            risk_level = "Critical"
        elif normalized_score >= 50:
            risk_level = "High"
        elif normalized_score >= 25:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        self.results["summary"]["risk_level"] = risk_level
        
        print(f"Found {len(self.issues)} issues: {severity_counts['High']} High, {severity_counts['Medium']} Medium, {severity_counts['Low']} Low")
        print(f"Overall risk level: {risk_level} ({normalized_score:.1f}/100)")
    
    def generate_report(self, output_format="text"):
        """Generate a formatted report of findings"""
        if output_format == "text":
            report = []
            
            # Title
            report.append("=" * 80)
            report.append(f"SECURITY ASSESSMENT REPORT: {self.target_url}")
            report.append("=" * 80)
            report.append("")
            
            # Summary
            report.append("SUMMARY")
            report.append("-" * 80)
            report.append(f"Target URL: {self.target_url}")
            report.append(f"Server IP: {self.results['reconnaissance'].get('server_ip', 'Unknown')}")
            report.append(f"Assessment Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            report.append(f"Risk Level: {self.results['summary']['risk_level']} ({self.results['summary']['risk_score']:.1f}/100)")
            report.append(f"Total Issues: {self.results['summary']['issues_count']}")
            report.append(f"High Severity: {self.results['summary']['severity_counts']['High']}")
            report.append(f"Medium Severity: {self.results['summary']['severity_counts']['Medium']}")
            report.append(f"Low Severity: {self.results['summary']['severity_counts']['Low']}")
            report.append("")
            
            # Technology Stack
            report.append("TECHNOLOGY STACK")
            report.append("-" * 80)
            tech_stack = self.results.get("tech_stack", {})
            report.append(f"Server: {tech_stack.get('server', 'Unknown')}")
            report.append(f"CMS: {tech_stack.get('cms', 'Unknown')}")
            
            if tech_stack.get("javascript_libraries"):
                report.append(f"JavaScript Libraries: {', '.join(tech_stack.get('javascript_libraries', []))}")
            
            if tech_stack.get("frameworks"):
                report.append(f"Frameworks: {', '.join(tech_stack.get('frameworks', []))}")
            
            if tech_stack.get("analytics"):
                report.append(f"Analytics: {', '.join(tech_stack.get('analytics', []))}")
            
            if tech_stack.get("third_party_services"):
                report.append(f"Third-party Services: {', '.join(tech_stack.get('third_party_services', []))}")
            
            report.append("")
            
            # SSL/TLS Information
            report.append("SSL/TLS CONFIGURATION")
            report.append("-" * 80)
            ssl_tls = self.results.get("ssl_tls", {})
            
            if ssl_tls.get("enabled", False):
                report.append("HTTPS: Enabled")
                
                if "certificate" in ssl_tls:
                    cert = ssl_tls["certificate"]
                    report.append(f"Certificate Expiry: {cert.get('notAfter', 'Unknown')}")
                    report.append(f"Days to Expiry: {cert.get('daysToExpiry', 'Unknown')}")
                    report.append(f"Issuer: {cert.get('issuer', {}).get('commonName', 'Unknown')}")
                
                if "protocol" in ssl_tls:
                    report.append(f"Protocol: {ssl_tls['protocol']}")
                
                if "cipher" in ssl_tls:
                    cipher = ssl_tls["cipher"]
                    report.append(f"Cipher: {cipher.get('name', 'Unknown')} ({cipher.get('bits', 'Unknown')} bits)")
            else:
                report.append("HTTPS: Not enabled")
            
            report.append("")
            
            # Security Headers
            report.append("SECURITY HEADERS")
            report.append("-" * 80)
            headers = self.results.get("headers", {})
            security_headers = headers.get("security_headers", {})
            
            for header, data in security_headers.items():
                status = "✓" if data["present"] else "✗"
                report.append(f"{status} {header}")
            
            report.append("")
            
            # Issues
            report.append("SECURITY ISSUES")
            report.append("-" * 80)
            
            if self.issues:
                # Sort issues by severity (High -> Medium -> Low)
                severity_order = {"High": 0, "Medium": 1, "Low": 2}
                sorted_issues = sorted(self.issues, key=lambda x: severity_order[x["severity"]])
                
                for i, issue in enumerate(sorted_issues, 1):
                    report.append(f"{i}. [{issue['severity']}] {issue['title']}")
                    report.append(f"   Description: {issue['description']}")
                    report.append(f"   Recommendation: {issue['recommendation']}")
                    report.append("")
            else:
                report.append("No security issues found.")
                report.append("")
            
            # Footer
            report.append("=" * 80)
            report.append("This report is for authorized security assessment purposes only.")
            report.append("All findings should be verified and remediated appropriately.")
            report.append("=" * 80)
            
            return "\n".join(report)
        
        elif output_format == "json":
            return json.dumps(self.results, indent=2)
        
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
    
    def visualize_results(self):
        """Generate visualizations of the assessment results"""
        # Create a figure with subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        # Severity distribution pie chart
        severity_counts = self.results["summary"]["severity_counts"]
        labels = [f"High ({severity_counts['High']})", 
                 f"Medium ({severity_counts['Medium']})", 
                 f"Low ({severity_counts['Low']})"]
        sizes = [severity_counts["High"], severity_counts["Medium"], severity_counts["Low"]]
        colors = ['#ff6b6b', '#feca57', '#48dbfb']
        
        if sum(sizes) > 0:  # Only create pie chart if there are issues
            ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
            ax1.axis('equal')
            ax1.set_title('Issues by Severity')
        else:
            ax1.text(0.5, 0.5, 'No issues found', horizontalalignment='center', verticalalignment='center')
            ax1.axis('off')
        
        # Security headers bar chart
        headers = self.results.get("headers", {}).get("security_headers", {})
        header_names = list(headers.keys())
        header_status = [1 if headers[h]["present"] else 0 for h in header_names]
        
        # Shorten header names for display
        short_names = [h.replace("Content-Security-Policy", "CSP")
                      .replace("Strict-Transport-Security", "HSTS")
                      .replace("X-Content-Type-Options", "X-Content-Type")
                      .replace("Permissions-Policy", "Permissions")
                      .replace("X-XSS-Protection", "X-XSS") for h in header_names]
        
        y_pos = range(len(short_names))
        ax2.barh(y_pos, header_status, color=['#48dbfb' if status else '#ff6b6b' for status in header_status])
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(short_names)
        ax2.set_xticks([0, 1])
        ax2.set_xticklabels(['Missing', 'Present'])
        ax2.set_title('Security Headers')
        
        plt.tight_layout()
        return fig

def main():
    """Main function to run the script"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Website Security Assessment Tool')
    parser.add_argument('url', help='Target URL to assess')
    parser.add_argument('--format', choices=['text', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--output', help='Output file path (default: print to console)')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    args = parser.parse_args()
    
    # Run assessment
    assessment = WebsiteSecurityAssessment(args.url)
    results = assessment.run_assessment()
    
    # Generate report
    report = assessment.generate_report(args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)
    
    # Generate visualizations if requested
    if args.visualize:
        fig = assessment.visualize_results()
        plt.show()

# For Google Colab usage
def run_assessment(url):
    """Run assessment from Google Colab"""
    assessment = WebsiteSecurityAssessment(url)
    results = assessment.run_assessment()
    
    # Print text report
    print(assessment.generate_report("text"))
    
    # Generate visualizations
    fig = assessment.visualize_results()
    plt.show()
    
    return results

if __name__ == "__main__":
    main()
