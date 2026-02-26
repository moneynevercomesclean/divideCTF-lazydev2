FROM python:3.9-slim

WORKDIR /app

RUN pip install --no-cache-dir flask "pyjwt==1.7.1" "cryptography<35.0" gunicorn

COPY . .

CMD ["gunicorn", "-b", ":8080", "app:app"]