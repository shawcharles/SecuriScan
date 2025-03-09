import unittest
from unittest.mock import patch, mock_open
from datetime import datetime
import os
import tempfile
import shutil

from securiscan.core.scanner import ScanTarget, TechnologyInfo, ScanStatistics, ScanResult

class TestScanResult(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_report_dir = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_report_dir)

    def test_scan_result_initialization(self):
        target = ScanTarget(
            url="http://example.com",
            ip="192.168.1.1",
            hostname="example.com",
            port=80,
            scheme="http",
            technologies=TechnologyInfo(
                version="2.4.41",
                server="Apache/2.4.41",
                cms="WordPress/5.6.2",
                programming_languages=["PHP"],
                frameworks=["WordPress"],
                javascript_libraries=["jQuery"],
                analytics=["Google Analytics"],
                third_party_services=["Cloudflare"],
                cdn="Cloudflare",
                waf="Cloudflare",
                operating_system="Linux",
                database="MySQL",
            ),
        )
        statistics = ScanStatistics(
            start_time=datetime.now(),
            end_time=datetime.now(),
            pages_scanned=10,
            requests_sent=20,
            vulnerabilities_found=5,
            scan_level="high",
        )
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[],
            statistics=statistics,
            risk_score=85.0,
            risk_level="high",
            scan_config={"scan_level": "high"},
            version="0.1.0",
        )
        self.assertEqual(result.id, "scan-001")
        self.assertEqual(result.target.url, "http://example.com")
        self.assertEqual(result.target.ip, "192.168.1.1")
        self.assertEqual(result.target.hostname, "example.com")
        self.assertEqual(result.target.port, 80)
        self.assertEqual(result.target.scheme, "http")
        self.assertEqual(result.target.technologies.version, "2.4.41")
        self.assertEqual(result.target.technologies.server, "Apache/2.4.41")
        self.assertEqual(result.target.technologies.cms, "WordPress/5.6.2")
        self.assertEqual(result.target.technologies.programming_languages, ["PHP"])
        self.assertEqual(result.target.technologies.frameworks, ["WordPress"])
        self.assertEqual(result.target.technologies.javascript_libraries, ["jQuery"])
        self.assertEqual(result.target.technologies.analytics, ["Google Analytics"])
        self.assertEqual(result.target.technologies.third_party_services, ["Cloudflare"])
        self.assertEqual(result.target.technologies.cdn, "Cloudflare")
        self.assertEqual(result.target.technologies.waf, "Cloudflare")
        self.assertEqual(result.target.technologies.operating_system, "Linux")
        self.assertEqual(result.target.technologies.database, "MySQL")
        self.assertEqual(result.statistics.start_time, statistics.start_time)
        self.assertEqual(result.statistics.end_time, statistics.end_time)
        self.assertEqual(result.statistics.pages_scanned, 10)
        self.assertEqual(result.statistics.requests_sent, 20)
        self.assertEqual(result.statistics.vulnerabilities_found, 5)
        self.assertEqual(result.statistics.scan_level, "high")
        self.assertEqual(result.risk_score, 85.0)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(result.scan_config, {"scan_level": "high"})
        self.assertEqual(result.version, "0.1.0")

    def test_generate_report_html(self):
        target = ScanTarget(
            url="http://example.com",
            ip="192.168.1.1",
            hostname="example.com",
            port=80,
            scheme="http",
            technologies=TechnologyInfo(
                server="Apache/2.4.41",
                cms="WordPress/5.6.2",
                programming_languages=["PHP"],
                frameworks=["WordPress"],
                javascript_libraries=["jQuery"],
                analytics=["Google Analytics"],
                third_party_services=["Cloudflare"],
                cdn="Cloudflare",
                waf="Cloudflare",
                operating_system="Linux",
                database="MySQL",
            ),
        )
        statistics = ScanStatistics(
            start_time=datetime.now(),
            end_time=datetime.now(),
            pages_scanned=10,
            requests_sent=20,
            vulnerabilities_found=5,
            scan_level="high",
        )
        result = ScanResult(
            id="scan-001",
            target=target,
            vulnerabilities=[],
            statistics=statistics,
            risk_score=85.0,
            risk_level="high",
            scan_config={"scan_level": "high"},
            version="0.1.0",
        )
        with patch("builtins.open", mock_open()) as mocked_file:
            result.generate_report("report.html", format="html")
            mocked_file.assert_called_once_with("report.html", "w")
            handle = mocked_file()
            handle.write.assert_called_once_with("<html><body><h1>Scan Report</h1></body></html>")

    def test_generate_report_json(self):
        target = ScanTarget(
            url="https://example.com",
            ip="93.184.216.34",
            hostname="example.com",
            port=443,
            scheme="https",
        )
        
        statistics = ScanStatistics(
            start_time=datetime.now(),
            end_time=datetime.now(),
            pages_scanned=1,
            requests_sent=1,
            vulnerabilities_found=0,
            scan_level="standard",
        )
        
        result = ScanResult(
            id="scan-001",
            target=target,
            statistics=statistics,
            vulnerabilities=[],
            risk_score=0,
            risk_level="Low",
            scan_config={},
            created_at=datetime.now(),
            version="0.1.0",
        )
        
        report_path = os.path.join(self.temp_report_dir, "report.json")
        
        # Mock the open function and json.dump to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file, \
             patch("json.dump") as mock_json_dump:
            result.generate_report(report_path, "json")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w")
            
            # Check that json.dump was called with the result dict
            mock_json_dump.assert_called_once()
            args, _ = mock_json_dump.call_args
            result_dict = args[0]
            
            # Assert various properties
            self.assertEqual(result_dict["id"], "scan-001")
            self.assertEqual(result_dict["target"]["url"], "https://example.com")
            self.assertEqual(result_dict["target"]["ip"], "93.184.216.34")
            self.assertEqual(result_dict["target"]["hostname"], "example.com")
            self.assertEqual(result_dict["target"]["port"], 443)
            self.assertEqual(result_dict["target"]["scheme"], "https")
            self.assertIsNotNone(result_dict["statistics"]["start_time"])
            self.assertIsNotNone(result_dict["statistics"]["end_time"])
            self.assertEqual(result_dict["statistics"]["pages_scanned"], 1)
            self.assertEqual(result_dict["statistics"]["requests_sent"], 1)
            self.assertEqual(result_dict["statistics"]["vulnerabilities_found"], 0)
            self.assertEqual(result_dict["statistics"]["scan_level"], "standard")
            self.assertEqual(result_dict["vulnerabilities"], [])
            self.assertEqual(result_dict["risk_score"], 0)
            self.assertEqual(result_dict["risk_level"], "Low")
            self.assertEqual(result_dict["scan_config"], {})
            self.assertIsNotNone(result_dict["created_at"])
            self.assertEqual(result_dict["version"], "0.1.0")

    def test_generate_report_unsupported_format(self):
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
            statistics=statistics,
            scan_config={},
            version="0.1.0",
        )
        
        report_path = os.path.join(self.temp_report_dir, "report.xyz")
        
        # Mock the open function to avoid actually writing to disk
        with patch("builtins.open", mock_open()) as mock_file:
            result.generate_report(report_path, "xyz")
            
            # Check that the file was opened for writing
            mock_file.assert_called_once_with(report_path, "w")
            
            # Check that some content was written
            handle = mock_file()
            handle.write.assert_called_once()
