Installation
============

SecuriScan is not currently available on PyPI and must be installed from source.

From Source
----------

.. code-block:: bash

    git clone https://github.com/shawcharles/SecuriScan.git
    cd SecuriScan
    pip install -e .

With Optional Dependencies
-------------------------

After installing from source, you can add optional dependencies:

.. code-block:: bash

    # For browser automation
    pip install -e ".[browser]"

    # For PDF report generation
    pip install -e ".[pdf]"

    # For development
    pip install -e ".[dev]"

    # For documentation
    pip install -e ".[docs]"

    # All optional dependencies
    pip install -e ".[all]"

Requirements
-----------

SecuriScan requires Python 3.8 or higher and the following dependencies:

* requests>=2.28.0
* beautifulsoup4>=4.11.0
* pydantic>=1.9.0
* typer>=0.6.0
* rich>=12.0.0
* jinja2>=3.1.0
* urllib3>=1.26.0
* certifi>=2022.5.18
