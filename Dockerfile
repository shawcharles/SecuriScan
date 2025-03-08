# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

# Set work directory
WORKDIR /app

# Install dependencies
COPY pyproject.toml setup.py ./
RUN pip install --no-cache-dir -e .

# Copy project
COPY . .

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos "" securiscan && \
    chown -R securiscan:securiscan /app
USER securiscan

# Set the entrypoint
ENTRYPOINT ["securiscan"]
CMD ["--help"]
