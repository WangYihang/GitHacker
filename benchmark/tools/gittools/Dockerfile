FROM python:3.12-slim

# gitdumper.sh shells out to `file` and `strings` to sniff downloaded objects
# and pull SHAs out of them. Without binutils it walks no object graph at all:
# it fetches its static filename list, saves two files, and stops — which the
# benchmark then scored as the tool recovering nothing.
RUN apt-get update && apt-get install -y git curl file binutils \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/internetwache/GitTools.git /opt/gittools

# Record version info (commit hash)
RUN cd /opt/gittools && git rev-parse --short HEAD > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
