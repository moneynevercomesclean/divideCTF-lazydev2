FROM python:3.9-slim

WORKDIR /app

RUN pip install flask "pyjwt==1.6.4" "cryptography<35.0"

COPY . .

EXPOSE 8080

CMD ["python", "app.py"]