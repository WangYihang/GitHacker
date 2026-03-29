FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/Ebryx/GitDump.git /opt/gitdump
RUN cd /opt/gitdump && pip install --no-cache-dir -r requirements.txt 2>/dev/null || true

# Record version info (commit hash)
RUN cd /opt/gitdump && git rev-parse --short HEAD > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
