Usage
=====

Command-line Interface
---------------------

SecuriScan provides a command-line interface for easy usage:

.. code-block:: bash

    # Basic scan
    securiscan scan https://example.com

    # Scan with specific level
    securiscan scan --level aggressive https://example.com

    # Save report
    securiscan scan --output report.html https://example.com

    # Continuous monitoring
    securiscan monitor --interval 24 https://example.com

    # List available scanner modules
    securiscan list-modules

Python API
---------

You can also use SecuriScan as a library in your Python applications:

Basic Scan
~~~~~~~~~

.. code-block:: python

    from securiscan import Scanner, ScanConfig, ScanLevel

    # Create scanner with custom configuration
    config = ScanConfig(
        scan_level=ScanLevel.STANDARD,
        max_depth=3,
        threads=10,
        timeout=30,
    )

    # Create scanner
    scanner = Scanner(config)

    # Run scan
    result = scanner.scan("https://example.com")

    # Print vulnerabilities
    for vuln in result.vulnerabilities:
        print(f"[{vuln.severity}] {vuln.name}: {vuln.description}")

    # Generate report
    result.generate_report("report.html", "html")

Continuous Monitoring
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

    from securiscan import Monitor, MonitorConfig, ScanConfig, ScanLevel

    # Create scan configuration
    scan_config = ScanConfig(
        scan_level=ScanLevel.PASSIVE,
        max_depth=2,
        threads=5,
        timeout=30,
    )

    # Create monitor configuration
    monitor_config = MonitorConfig(
        interval=3600,  # 1 hour
        scan_config=scan_config,
        report_dir="reports",
    )

    # Create monitor
    monitor = Monitor(monitor_config)

    # Define callback function for scan results
    def on_scan_complete(result):
        print(f"Scan completed: {len(result.vulnerabilities)} vulnerabilities found")
        
    # Start monitoring
    monitor.start("https://example.com", on_scan_complete)

Custom Scanner
~~~~~~~~~~~~

You can create custom scanners by extending the BaseScanner class:

.. code-block:: python

    from securiscan import BaseScanner, Vulnerability, Severity, Confidence

    class CustomScanner(BaseScanner):
        """Custom scanner for detecting specific vulnerabilities."""

        def run(self, target):
            """Run the custom scanner.
            
            Args:
                target: Scan target
                
            Returns:
                List of vulnerabilities found
            """
            vulnerabilities = []
            
            # Your custom scanning logic here
            
            return vulnerabilities
            
    # Register the custom scanner
    scanner.register_scanner(CustomScanner)
