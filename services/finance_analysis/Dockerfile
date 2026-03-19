FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and shared module
COPY app_b_finance.py .
COPY ../shared shared/

# Add shared to Python path
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
    CMD curl -f http://localhost:8002/health || exit 1

# Run application
CMD ["python", "app_b_finance.py"]
