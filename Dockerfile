# Build stage
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies in a virtual environment
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application files
COPY main.py /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

# Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 appuser && \
    chown -R appuser:appuser /app

# Use non-root user
USER appuser

# Set PATH to use virtual environment
ENV PATH="/opt/venv/bin:$PATH"

EXPOSE 2000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "2000"]
