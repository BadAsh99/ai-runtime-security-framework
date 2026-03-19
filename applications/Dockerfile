FROM python:3.11-slim

WORKDIR /app

COPY applications/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY applications/ .

ENV PYTHONPATH=/app

# Default command — overridden per-service in docker-compose.yml
CMD ["uvicorn", "app_a_content:app", "--host", "0.0.0.0", "--port", "8001"]
