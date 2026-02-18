FROM alpine:3.20 AS cli-fetch
RUN apk add --no-cache wget
ARG TA_CLI_SHA256=f8c047de5e2be82778a9e0cd3312024fbdaf5ed4adce27c550c1f48e0beb1306
RUN wget -O /ta-cli https://github.com/chris102994/toonamiaftermath-cli/releases/download/v1.1.1/toonamiaftermath-cli_v1.1.1_linux_amd64 \
    && echo "${TA_CLI_SHA256}  /ta-cli" | sha256sum -c - \
    && chmod +x /ta-cli

FROM python:3.12-alpine3.20
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    WEB_DIR=/web \
    PORT=7004 \
    CRON_SCHEDULE="0 3 * * *"

RUN apk add --no-cache bash ca-certificates gcompat libc6-compat libstdc++ tzdata

WORKDIR /app

# Copy only requirements first for better cache hits
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Then copy app code and web assets
# Ensure Python package layout: place code under /app/app so 'app.server' resolves
COPY app /app/app
COPY web /web
COPY --from=cli-fetch /ta-cli /usr/local/bin/toonamiaftermath-cli

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:7004/health || exit 1

EXPOSE 7004
VOLUME ["/data"]

CMD ["uvicorn", "app.server:create_app", "--host", "0.0.0.0", "--port", "7004", "--factory"]
