FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY logger_service.py .

# Data directory for SQLite
RUN mkdir -p /data

EXPOSE 5001

CMD ["python", "logger_service.py"]
