FROM python:3.12-slim

RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/internetwache/GitTools.git /opt/gittools

# Record version info (commit hash)
RUN cd /opt/gittools && git rev-parse --short HEAD > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
