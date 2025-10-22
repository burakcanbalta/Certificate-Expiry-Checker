FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

VOLUME /app/reports
VOLUME /app/data

CMD ["python", "certificate_checker.py", "--monitor", "--interval", "3600"]
