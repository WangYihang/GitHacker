FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/lijiejie/GitHack.git /opt/githack

# Record version info (commit hash)
RUN cd /opt/githack && git rev-parse --short HEAD > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
