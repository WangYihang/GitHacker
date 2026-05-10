FROM python:3.12-slim AS builder
RUN pip install --no-cache-dir uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --no-install-project --no-dev
COPY githacker ./githacker
COPY README.md ./
RUN uv sync --no-dev

FROM python:3.12-slim
RUN useradd -r -u 1000 -m -d /home/githacker githacker \
    && apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app /app
USER githacker
ENV PATH="/app/.venv/bin:${PATH}"
ENTRYPOINT ["githacker"]
