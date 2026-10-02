FROM python:3.11-slim

WORKDIR /app

# System deps: docker cli, curl, zstd for backup
RUN apt-get update && apt-get install -y \
    docker.io procps curl zstd apt-utils \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# App files
COPY . .

EXPOSE 3000

CMD ["python", "app.py"]
