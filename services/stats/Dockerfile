FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY stats_service.py .

EXPOSE 5003

CMD ["python", "stats_service.py"]
