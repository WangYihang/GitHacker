FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Build context for THIS image is the project root (see build_image in
# benchmark/docker.py), so we can install the local source — the benchmark
# is supposed to measure the current branch, not whatever's on PyPI.
COPY pyproject.toml /src/
COPY README.md /src/
COPY githacker /src/githacker
RUN pip install --no-cache-dir /src

RUN pip show githacker | grep -E '^Version:' | cut -d' ' -f2 \
  | awk '{print $1 "+local"}' > /tool-version.txt

COPY benchmark/tools/githacker/run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
