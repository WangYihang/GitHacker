FROM rust:1.82-slim AS builder

RUN apt-get update && apt-get install -y git pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/holly-hacker/git-dumper.git /opt/git-dumper-hh \
    && cd /opt/git-dumper-hh && git rev-parse --short HEAD > /tmp/tool-version.txt \
    && cargo build --release 2>/dev/null || echo "build-failed" > /tmp/tool-version.txt

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y git ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /opt/git-dumper-hh/target/release/git-dumper /usr/local/bin/git-dumper-hh 2>/dev/null || true
COPY --from=builder /tmp/tool-version.txt /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
