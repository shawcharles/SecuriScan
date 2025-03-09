Examples
========

SecuriScan comes with several example scripts to help you get started. These examples demonstrate different aspects of the framework and can be used as a starting point for your own security testing scripts.

Basic Scan
---------

The `basic_scan.py` example demonstrates how to use the SecuriScan framework to perform a basic security scan on a website.

.. literalinclude:: ../examples/basic_scan.py
   :language: python
   :linenos:

To run this example:

.. code-block:: bash

    python examples/basic_scan.py https://example.com --level passive --output report.html

Continuous Monitoring
-------------------

The `continuous_monitoring.py` example demonstrates how to use the SecuriScan framework to continuously monitor a website for security issues.

.. literalinclude:: ../examples/continuous_monitoring.py
   :language: python
   :linenos:

To run this example:

.. code-block:: bash

    python examples/continuous_monitoring.py https://example.com --interval 3600 --output-dir reports

Custom Scanner
------------

The `custom_scanner.py` example demonstrates how to create a custom scanner module for the SecuriScan framework. This example creates a scanner that detects email addresses in web pages.

.. literalinclude:: ../examples/custom_scanner.py
   :language: python
   :linenos:

To run this example:

.. code-block:: bash

    python examples/custom_scanner.py https://example.com --output report.html

Modified Examples
---------------

The repository also includes modified versions of the examples that use the ReportGenerator class for proper report generation:

- `modified_basic_scan.py`
- `modified_continuous_monitoring.py`
- `modified_custom_scanner.py`

These modified examples demonstrate how to use the more comprehensive ReportGenerator class from the reporting package, which creates detailed reports.
