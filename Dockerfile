FROM alpine:3.20 AS cli-fetch
RUN apk add --no-cache wget
RUN wget -O /ta-cli https://github.com/chris102994/toonamiaftermath-cli/releases/download/v1.1.1/toonamiaftermath-cli_v1.1.1_linux_amd64 \
    && chmod +x /ta-cli

FROM python:3.12-alpine3.20
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    WEB_DIR=/web \
    PORT=7004 \
    CRON_SCHEDULE="0 3 * * *"

RUN apk add --no-cache bash ca-certificates tzdata

WORKDIR /app
COPY app /app
COPY web /web
COPY requirements.txt /app/requirements.txt
COPY --from=cli-fetch /ta-cli /usr/local/bin/toonamiaftermath-cli

RUN pip install --no-cache-dir -r /app/requirements.txt

EXPOSE 7004
VOLUME ["/data"]

CMD ["uvicorn", "app.server:create_app", "--host", "0.0.0.0", "--port", "7004", "--factory"]
