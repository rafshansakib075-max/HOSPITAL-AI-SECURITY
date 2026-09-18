# Railway / Python app
FROM python:3.11-slim

WORKDIR /code

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt \
 && pip install --no-cache-dir "gunicorn>=22,<24"

COPY . .

# Bake the seeded database + trained ML models into the image
ENV FLASK_DEBUG=0
RUN python seed_db.py

# Use Railway's PORT variable (defaults to 8000)
EXPOSE 8000
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120"]
