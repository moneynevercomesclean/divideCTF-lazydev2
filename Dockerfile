FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# (Optional but helpful) build deps for some crypto wheels in rare cases
# RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    flask \
    "pyjwt==1.7.1" \
    "cryptography<35.0" \
    gunicorn

COPY . .

# Cloud Run sets $PORT, but we bind gunicorn to it explicitly
CMD exec gunicorn --bind ":${PORT:-8080}" --workers 1 --threads 8 --timeout 0 app:app