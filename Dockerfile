# Hugging Face Spaces (Docker SDK) - free, no card, full AI mode.
# Space settings: SDK = Docker, hardware = CPU basic (free).
# The container must listen on port 7860 (set via PORT below).
FROM python:3.11-slim

WORKDIR /code

# System deps for shap/sklearn wheels (cp311 manylinux, no compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY requirements-ml.txt .
RUN pip install --no-cache-dir -r requirements-ml.txt \
 && pip install --no-cache-dir "gunicorn>=22,<24"

COPY . .

# Bake the seeded database + trained ML models into the image so the
# Space works immediately on boot (container disk is ephemeral).
ENV FLASK_DEBUG=0
RUN python seed_db.py

ENV PORT=7860
EXPOSE 7860
CMD ["sh", "-c", "gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120"]
