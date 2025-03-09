Contributing
============

Contributions are welcome! Please feel free to submit a Pull Request.

Development Setup
---------------

1. Fork the repository
2. Clone your fork:

   .. code-block:: bash

       git clone https://github.com/your-username/SecuriScan.git
       cd SecuriScan

3. Install development dependencies:

   .. code-block:: bash

       pip install -e ".[dev]"

4. Set up pre-commit hooks:

   .. code-block:: bash

       pre-commit install

Development Workflow
------------------

1. Create a new branch for your feature:

   .. code-block:: bash

       git checkout -b feature/amazing-feature

2. Make your changes
3. Run tests:

   .. code-block:: bash

       pytest

4. Run linters:

   .. code-block:: bash

       flake8 securiscan
       black securiscan
       isort securiscan
       mypy securiscan

5. Commit your changes:

   .. code-block:: bash

       git commit -m "Add some amazing feature"

6. Push to your branch:

   .. code-block:: bash

       git push origin feature/amazing-feature

7. Open a Pull Request

Pull Request Guidelines
---------------------

1. Update the README.md with details of changes to the interface, if applicable.
2. Update the documentation if necessary.
3. The PR should work for Python 3.8, 3.9, 3.10, and 3.11.
4. Ensure all tests pass.

Code Style
---------

This project uses:

* Black for code formatting
* isort for import sorting
* flake8 for linting
* mypy for type checking

All code should be properly typed and documented with docstrings following the Google style.

Testing
------

All new features should include tests. This project uses pytest for testing.

To run tests:

.. code-block:: bash

    pytest

To run tests with coverage:

.. code-block:: bash

    pytest --cov=securiscan

Documentation
------------

To build the documentation locally:

.. code-block:: bash

    cd docs
    make html

The documentation will be available in the `_build/html` directory.
