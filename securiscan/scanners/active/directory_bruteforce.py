"""
Directory Bruteforce Scanner Module.

This module performs directory and file bruteforcing to discover hidden content.
"""

import asyncio
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set

import aiohttp
import requests
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


class DirectoryBruteforceScanner(BaseScanner):
    """Scanner for discovering hidden directories and files through bruteforcing."""

    # Default wordlists
    DEFAULT_DIRECTORY_WORDLIST = [
        "admin", "administrator", "backup", "backups", "config", "dashboard", "db",
        "debug", "default", "dev", "files", "home", "images", "img", "index", "js",
        "login", "logs", "old", "panel", "private", "root", "secret", "secrets",
        "secure", "security", "server-status", "setup", "site", "staff", "staging",
        "static", "stats", "status", "temp", "test", "testing", "tmp", "upload",
        "uploads", "user", "users", "web", "wp-admin", "wp-content", "wp-includes",
    ]
    
    DEFAULT_FILE_WORDLIST = [
        ".env", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd", ".svn/entries",
        "README", "README.md", "Thumbs.db", "Web.config", "backup.sql", "config.php",
        "config.yml", "credentials.txt", "database.sql", "db.sql", "debug.log",
        "error.log", "index.php", "info.php", "login.php", "phpinfo.php", "robots.txt",
        "server-status", "sitemap.xml", "wp-config.php",
    ]
    
    DEFAULT_EXTENSIONS = [
        ".bak", ".conf", ".config", ".json", ".log", ".old", ".orig", ".php", ".sql",
        ".tar", ".tar.gz", ".txt", ".xml", ".zip",
    ]

    def run(self, target: ScanTarget) -> List[Vulnerability]:
        """Run the directory bruteforce scanner.

        Args:
            target: Scan target

        Returns:
            List of vulnerabilities found
        """
        self.logger.info(f"Bruteforcing directories and files on {target.url}")
        vulnerabilities = []

        try:
            # Get base URL without path
            base_url = self._get_base_url(target.url)
            
            # Get wordlists
            directory_wordlist = self._get_directory_wordlist()
            file_wordlist = self._get_file_wordlist()
            
            # Run bruteforce
            found_resources = asyncio.run(self._bruteforce(
                base_url=base_url,
                directory_wordlist=directory_wordlist,
                file_wordlist=file_wordlist,
            ))
            
            # Create vulnerabilities for interesting findings
            if found_resources:
                vuln = self._create_hidden_resource_vulnerability(target.url, found_resources)
                vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error bruteforcing directories and files: {str(e)}", exc_info=True)
            return []

    def _get_base_url(self, url: HttpUrl) -> str:
        """Get base URL without path.

        Args:
            url: Target URL

        Returns:
            Base URL
        """
        from urllib.parse import urlparse
        
        parsed_url = urlparse(str(url))
        return f"{parsed_url.scheme}://{parsed_url.netloc}"

    def _get_directory_wordlist(self) -> List[str]:
        """Get directory wordlist.

        Returns:
            Directory wordlist
        """
        # In a real implementation, this would load from a file or configuration
        return self.DEFAULT_DIRECTORY_WORDLIST

    def _get_file_wordlist(self) -> List[str]:
        """Get file wordlist.

        Returns:
            File wordlist
        """
        # In a real implementation, this would load from a file or configuration
        return self.DEFAULT_FILE_WORDLIST

    async def _bruteforce(
        self,
        base_url: str,
        directory_wordlist: List[str],
        file_wordlist: List[str],
    ) -> List[Dict[str, str]]:
        """Perform directory and file bruteforcing.

        Args:
            base_url: Base URL
            directory_wordlist: Directory wordlist
            file_wordlist: File wordlist

        Returns:
            List of found resources
        """
        found_resources = []
        
        # Create a list of URLs to check
        urls_to_check = []
        
        # Add directory URLs
        for directory in directory_wordlist:
            urls_to_check.append({
                "url": f"{base_url}/{directory}/",
                "type": "directory",
                "name": directory,
            })
        
        # Add file URLs
        for file in file_wordlist:
            urls_to_check.append({
                "url": f"{base_url}/{file}",
                "type": "file",
                "name": file,
            })
        
        # Add files with extensions to directories
        for directory in [""] + directory_wordlist:
            for file in ["index", "admin", "login", "config", "backup", "test"]:
                for ext in self.DEFAULT_EXTENSIONS:
                    path = f"{directory}/{file}{ext}" if directory else f"{file}{ext}"
                    urls_to_check.append({
                        "url": f"{base_url}/{path}",
                        "type": "file",
                        "name": path,
                    })
        
        # Set up semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)  # Limit to 10 concurrent requests
        
        # Create a session
        async with aiohttp.ClientSession() as session:
            # Create tasks
            tasks = []
            for url_info in urls_to_check:
                task = asyncio.ensure_future(self._check_url(session, semaphore, url_info))
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks)
            
            # Filter out None results
            found_resources = [result for result in results if result]
        
        return found_resources

    async def _check_url(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        url_info: Dict[str, str],
    ) -> Optional[Dict[str, str]]:
        """Check if a URL exists.

        Args:
            session: aiohttp session
            semaphore: asyncio semaphore
            url_info: URL information

        Returns:
            URL information if found, None otherwise
        """
        async with semaphore:
            try:
                # Send request
                async with session.get(
                    url_info["url"],
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    # Check if the resource exists
                    if 200 <= response.status < 300:
                        # Resource exists
                        url_info["status"] = response.status
                        url_info["content_type"] = response.headers.get("Content-Type", "")
                        url_info["content_length"] = response.headers.get("Content-Length", "")
                        return url_info
                    elif response.status == 401 or response.status == 403:
                        # Resource exists but is protected
                        url_info["status"] = response.status
                        url_info["content_type"] = response.headers.get("Content-Type", "")
                        url_info["content_length"] = response.headers.get("Content-Length", "")
                        return url_info
                    elif 300 <= response.status < 400:
                        # Resource redirects
                        url_info["status"] = response.status
                        url_info["redirect_location"] = response.headers.get("Location", "")
                        return url_info
            except Exception as e:
                self.logger.debug(f"Error checking URL {url_info['url']}: {str(e)}")
            
            return None

    def _create_hidden_resource_vulnerability(
        self,
        url: HttpUrl,
        found_resources: List[Dict[str, str]],
    ) -> Vulnerability:
        """Create a vulnerability for hidden resources.

        Args:
            url: Target URL
            found_resources: List of found resources

        Returns:
            Vulnerability object
        """
        # Determine severity based on the types of resources found
        severity = Severity.LOW
        for resource in found_resources:
            name = resource["name"].lower()
            if any(sensitive in name for sensitive in ["admin", "config", "backup", "db", "sql", "password", "secret", "key"]):
                severity = Severity.MEDIUM
                break
        
        # Create evidence
        evidence = Evidence(
            type="hidden_resources",
            data=found_resources,
            description=f"Found {len(found_resources)} hidden resources",
            timestamp=datetime.now(),
        )
        
        # Create vulnerability
        return Vulnerability(
            id=str(uuid.uuid4()),
            name="Hidden Resources Discovered",
            type=VulnerabilityType.INFORMATION_DISCLOSURE,
            severity=severity,
            confidence=Confidence.HIGH,
            description=f"Directory and file bruteforcing discovered {len(found_resources)} hidden resources that could potentially expose sensitive information or functionality.",
            url=url,
            path=url.path,
            evidence=[evidence],
            remediation="Review the discovered resources and ensure they do not expose sensitive information. Consider restricting access to these resources or removing them if they are not needed.",
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information",
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            ],
            cwe=538,  # CWE-538: File and Directory Information Exposure
            tags={"information-disclosure", "bruteforce", "hidden-resources"},
        )
