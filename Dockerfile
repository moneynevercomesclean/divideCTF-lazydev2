FROM python:3.9-slim

WORKDIR /app

RUN pip install "pyjwt==1.7.1" "cryptography"

COPY . .

EXPOSE 8080

CMD ["python", "app.py"]