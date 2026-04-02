FROM python:3.11-slim

LABEL description="SOC Lab — Detection and correlation scripts"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scripts/ ./scripts/
COPY sigma/ ./sigma/

CMD ["python3", "scripts/detection_engine.py"]