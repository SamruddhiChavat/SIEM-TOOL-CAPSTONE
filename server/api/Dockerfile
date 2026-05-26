FROM python:3.11-slim

WORKDIR /app

# Install system deps: gcc + libpq for psycopg2, curl for healthcheck
RUN apt-get update && apt-get install -y gcc libpq-dev curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Startup: run DB migrations / admin seed, then start the API
CMD ["sh", "-c", "python create_admin.py || true && uvicorn main:app --host 0.0.0.0 --port 8000"]
