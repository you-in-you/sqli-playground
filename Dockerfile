FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc default-libmysqlclient-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_APP=app.main
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host=0.0.0.0", "--port=5000"]
