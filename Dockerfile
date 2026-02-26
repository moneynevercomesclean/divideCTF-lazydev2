FROM python:3.9-slim

WORKDIR /app

COPY app .

RUN pip install flask pyjwt==2.8.0

EXPOSE 8080

CMD ["python", "app.py"]