FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Install nc
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

COPY user-service.sh /user-service.sh
RUN chmod +x /user-service.sh

ENTRYPOINT ["/user-service.sh"]

EXPOSE 8000

CMD gunicorn user_service.wsgi:application --bind 0.0.0.0:$PORT
