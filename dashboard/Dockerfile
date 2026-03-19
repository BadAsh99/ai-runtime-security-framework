FROM python:3.11-slim

WORKDIR /app

COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/ ./dashboard/
COPY scanner/ ./scanner/
COPY gateway/validators/ ./gateway/validators/
COPY gateway/middleware/ ./gateway/middleware/

ENV PYTHONPATH=/app

CMD ["streamlit", "run", "dashboard/streamlit_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
