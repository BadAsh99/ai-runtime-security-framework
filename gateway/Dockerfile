FROM python:3.11-slim

WORKDIR /app

COPY gateway/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway/ ./gateway/
COPY applications/shared_llm_client.py ./applications/
COPY scanner/ ./scanner/

ENV PYTHONPATH=/app

CMD ["uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "8000"]
