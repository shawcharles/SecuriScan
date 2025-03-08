"""
Technology Detection Scanner Module.

This module analyzes websites to detect technologies in use.
"""

import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set

import requests
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from securiscan.core.result import (
    Confidence,
    Evidence,
    ScanTarget,
    Severity,
    TechnologyInfo,
    Vulnerability,
    VulnerabilityType,
)
from securiscan.core.scanner import BaseScanner


class TechnologyDetectionScanner(BaseScanner):
    """Scanner for detecting technologies used by a website."""

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the technology detection scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Detecting technologies for {target.url}")
        vulnerabilities = []

        try:
            # Send request to the target
            response = self.scanner.send_request(target.url)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, "html.parser")
            
            # Detect technologies
            technologies = self._detect_technologies(response, soup)
            
            # Update target with detected technologies
            target.technologies = technologies
            
            # Check for outdated or vulnerable technologies
            outdated_techs = self._check_outdated_technologies(technologies)
            if outdated_techs:
                vuln = self._create_outdated_tech_vulnerability(target.url, outdated_techs)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error detecting technologies: {str(e)}", exc_info=True)
            return []

    def _detect_technologies(self, response: requests.Response, soup: BeautifulSoup) -> TechnologyInfo:
        """Detect technologies used by a website.

        Args:
            response: HTTP response
            soup: BeautifulSoup object

        Returns:
            TechnologyInfo object with detected technologies
        """
        technologies = TechnologyInfo()
        
        # Detect server
        if "Server" in response.headers:
            technologies.server = response.headers["Server"]
        
        # Detect CMS
        technologies.cms = self._detect_cms(response, soup)
        
        # Detect JavaScript libraries
        technologies.javascript_libraries = self._detect_js_libraries(soup)
        
        # Detect frameworks
        technologies.frameworks = self._detect_frameworks(response, soup)
        
        # Detect analytics
        technologies.analytics = self._detect_analytics(soup)
        
        # Detect third-party services
        technologies.third_party_services = self._detect_third_party_services(response, soup)
        
        return technologies

    def _detect_cms(self, response: requests.Response, soup: BeautifulSoup) -> Optional[str]:
        """Detect Content Management System.

        Args:
            response: HTTP response
            soup: BeautifulSoup object

        Returns:
            CMS name if detected, None otherwise
        """
        html_content = response.text.lower()
        
        # WordPress
        if any(pattern in html_content for pattern in ["wp-content", "wp-includes", "wp-json"]):
            return "WordPress"
        
        # Check meta generator tag
        meta_generator = soup.find("meta", attrs={"name": "generator"})
        if meta_generator and meta_generator.get("content"):
            content = meta_generator.get("content").lower()
            
            if "wordpress" in content:
                return "WordPress"
            elif "drupal" in content:
                return "Drupal"
            elif "joomla" in content:
                return "Joomla"
            elif "wix" in content:
                return "Wix"
            elif "shopify" in content:
                return "Shopify"
            elif "squarespace" in content:
                return "Squarespace"
        
        # Drupal
        if "drupal" in html_content or soup.find("link", attrs={"rel": "shortcut icon", "href": lambda x: x and "drupal" in x.lower()}):
            return "Drupal"
        
        # Joomla
        if "joomla" in html_content or soup.find("meta", attrs={"name": "generator", "content": lambda x: x and "joomla" in x.lower()}):
            return "Joomla"
        
        # Shopify
        if "shopify" in html_content or "cdn.shopify.com" in html_content:
            return "Shopify"
        
        # Wix
        if "wix.com" in html_content or "_wix" in html_content:
            return "Wix"
        
        # Squarespace
        if "squarespace" in html_content or "static1.squarespace.com" in html_content:
            return "Squarespace"
        
        # Magento
        if "magento" in html_content or "mage/cookies" in html_content:
            return "Magento"
        
        return None

    def _detect_js_libraries(self, soup: BeautifulSoup) -> List[str]:
        """Detect JavaScript libraries.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of detected JavaScript libraries
        """
        libraries = []
        html_content = str(soup).lower()
        
        # jQuery
        if "jquery" in html_content:
            libraries.append("jQuery")
        
        # React
        if "react" in html_content or "_reactrootid" in html_content:
            libraries.append("React")
        
        # Angular
        if "angular" in html_content or "ng-app" in html_content:
            libraries.append("Angular")
        
        # Vue.js
        if "vue" in html_content or "v-bind" in html_content or "v-on" in html_content:
            libraries.append("Vue.js")
        
        # Bootstrap
        if "bootstrap" in html_content:
            libraries.append("Bootstrap")
        
        # Lodash
        if "lodash" in html_content or "_.map" in html_content or "_.filter" in html_content:
            libraries.append("Lodash")
        
        # Moment.js
        if "moment" in html_content or "moment.js" in html_content:
            libraries.append("Moment.js")
        
        # D3.js
        if "d3" in html_content or "d3.js" in html_content:
            libraries.append("D3.js")
        
        # Check script tags
        for script in soup.find_all("script", src=True):
            src = script["src"].lower()
            
            if "jquery" in src:
                if "jQuery" not in libraries:
                    libraries.append("jQuery")
            elif "react" in src:
                if "React" not in libraries:
                    libraries.append("React")
            elif "angular" in src:
                if "Angular" not in libraries:
                    libraries.append("Angular")
            elif "vue" in src:
                if "Vue.js" not in libraries:
                    libraries.append("Vue.js")
            elif "bootstrap" in src:
                if "Bootstrap" not in libraries:
                    libraries.append("Bootstrap")
            elif "lodash" in src or "underscore" in src:
                if "Lodash" not in libraries:
                    libraries.append("Lodash")
            elif "moment" in src:
                if "Moment.js" not in libraries:
                    libraries.append("Moment.js")
            elif "d3" in src:
                if "D3.js" not in libraries:
                    libraries.append("D3.js")
        
        return libraries

    def _detect_frameworks(self, response: requests.Response, soup: BeautifulSoup) -> List[str]:
        """Detect web frameworks.

        Args:
            response: HTTP response
            soup: BeautifulSoup object

        Returns:
            List of detected frameworks
        """
        frameworks = []
        html_content = str(soup).lower()
        headers = response.headers
        
        # Ruby on Rails
        if "rails" in html_content or "ruby on rails" in html_content:
            frameworks.append("Ruby on Rails")
        
        # Django
        if "django" in html_content or "csrftoken" in html_content:
            frameworks.append("Django")
        
        # Laravel
        if "laravel" in html_content or "csrf-token" in html_content:
            frameworks.append("Laravel")
        
        # Express.js
        if "express" in html_content or "node_modules" in html_content:
            frameworks.append("Express.js")
        
        # ASP.NET
        if "asp.net" in html_content or "__viewstate" in html_content:
            frameworks.append("ASP.NET")
        
        # Check for PHP
        if "X-Powered-By" in headers and "php" in headers["X-Powered-By"].lower():
            frameworks.append("PHP")
        
        # Check for Spring
        if "spring" in html_content or "org.springframework" in html_content:
            frameworks.append("Spring")
        
        # Check for Flask
        if "flask" in html_content:
            frameworks.append("Flask")
        
        return frameworks

    def _detect_analytics(self, soup: BeautifulSoup) -> List[str]:
        """Detect analytics services.

        Args:
            soup: BeautifulSoup object

        Returns:
            List of detected analytics services
        """
        analytics = []
        html_content = str(soup).lower()
        
        # Google Analytics
        if "google-analytics.com" in html_content or "ga(" in html_content or "gtag" in html_content:
            analytics.append("Google Analytics")
        
        # Google Tag Manager
        if "googletagmanager.com" in html_content or "gtm.js" in html_content:
            analytics.append("Google Tag Manager")
        
        # Facebook Pixel
        if "connect.facebook.net" in html_content or "fbq(" in html_content:
            analytics.append("Facebook Pixel")
        
        # Hotjar
        if "hotjar" in html_content or "hjsetting" in html_content:
            analytics.append("Hotjar")
        
        # Matomo/Piwik
        if "matomo" in html_content or "piwik" in html_content:
            analytics.append("Matomo/Piwik")
        
        # Mixpanel
        if "mixpanel" in html_content:
            analytics.append("Mixpanel")
        
        # Segment
        if "segment.com" in html_content or "analytics.js" in html_content:
            analytics.append("Segment")
        
        return analytics

    def _detect_third_party_services(self, response: requests.Response, soup: BeautifulSoup) -> List[str]:
        """Detect third-party services.

        Args:
            response: HTTP response
            soup: BeautifulSoup object

        Returns:
            List of detected third-party services
        """
        services = []
        html_content = str(soup).lower()
        headers = response.headers
        
        # Cloudflare
        if "cloudflare" in html_content or "cf-ray" in headers or "__cf" in html_content:
            services.append("Cloudflare")
        
        # AWS
        if "amazonaws.com" in html_content or "aws-" in html_content:
            services.append("AWS")
        
        # Akamai
        if "akamai" in html_content or "akamai" in str(headers).lower():
            services.append("Akamai")
        
        # Stripe
        if "stripe.com" in html_content or "stripe." in html_content:
            services.append("Stripe")
        
        # PayPal
        if "paypal.com" in html_content or "paypal" in html_content:
            services.append("PayPal")
        
        # Disqus
        if "disqus.com" in html_content or "disqus" in html_content:
            services.append("Disqus")
        
        # Intercom
        if "intercom" in html_content or "intercomsettings" in html_content:
            services.append("Intercom")
        
        # Zendesk
        if "zendesk" in html_content or "zdassets" in html_content:
            services.append("Zendesk")
        
        # Hubspot
        if "hubspot" in html_content or "hs-script" in html_content:
            services.append("Hubspot")
        
        # Mailchimp
        if "mailchimp" in html_content or "mc.js" in html_content:
            services.append("Mailchimp")
        
        return services

    def _check_outdated_technologies(self, technologies: TechnologyInfo) -> Dict[str, str]:
        """Check for outdated or vulnerable technologies.

        Args:
            technologies: Detected technologies

        Returns:
            Dictionary of outdated technologies and their versions
        """
        outdated_techs = {}
        
        # This is a simplified check and would need a database of known vulnerabilities
        # For a real implementation, you would check against a database of known vulnerable versions
        
        # Check JavaScript libraries
        for library in technologies.javascript_libraries:
            # Example check for jQuery (simplified)
            if library == "jQuery":
                # In a real implementation, you would extract the version and check against a database
                outdated_techs[library] = "Unknown version"
        
        # Check CMS
        if technologies.cms:
            # Example check for WordPress (simplified)
            if technologies.cms == "WordPress":
                # In a real implementation, you would extract the version and check against a database
                outdated_techs[technologies.cms] = "Unknown version"
        
        return outdated_techs

    def _create_outdated_tech_vulnerability(
        self, url: HttpUrl, outdated_techs: Dict[str, str]
    ) -> Vulnerability:
        """Create a vulnerability for outdated technologies.

        Args:
            url: Target URL
            outdated_techs: Dictionary of outdated technologies and their versions

        Returns:
            Vulnerability object
        """
        # Create evidence
        evidence = Evidence(
            type="outdated_technologies",
            data=outdated_techs,
            description=f"Potentially outdated technologies: {', '.join(outdated_techs.keys())}",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Potentially Outdated Technologies",
            type=VulnerabilityType.VULNERABLE_COMPONENTS,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=f"The website uses potentially outdated technologies that may contain security vulnerabilities: {', '.join(outdated_techs.keys())}.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Update all libraries and frameworks to their latest versions to address potential security vulnerabilities.",
            references=[
                "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                "https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html",
            ],
            cwe=1026,  # CWE-1026: Weaknesses in OWASP Top Ten (2017)
            tags={"outdated-components", "vulnerable-libraries"},
        )
