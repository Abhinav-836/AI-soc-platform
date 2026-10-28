# AI SOC Platform (API + dashboard). Build from the repository root:
#   docker build -f docker/Dockerfile -t ai-soc .
#   docker run -p 8080:8080 -v soc-data:/data ai-soc
# The compose file referenced docker/Dockerfile, which did not exist.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    SOC_DATA_DIR=/data SOC_HOST=0.0.0.0 SOC_PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY src/ ./src/
COPY config/ ./config/
COPY scripts/ ./scripts/
COPY run.py .

# Pre-train the anomaly model so the container is ready immediately
RUN SOC_DATA_DIR=/app/seed python scripts/train_models.py > /dev/null

RUN useradd --create-home --uid 10001 soc && mkdir -p /data && chown -R soc /data /app/seed
USER soc
VOLUME ["/data"]
EXPOSE 8080 5514/udp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status == 200 else 1)"

# copy the pre-trained model into the data volume on first start
CMD ["sh", "-c", "mkdir -p /data/models && cp -n /app/seed/models/* /data/models/ 2>/dev/null; exec python run.py"]
