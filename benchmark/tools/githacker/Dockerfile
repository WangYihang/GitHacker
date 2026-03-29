FROM python:3.12-slim

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir git+https://github.com/WangYihang/GitHacker.git

# Record version info (commit from git repo)
RUN pip show githacker | grep -E '^Version:' | cut -d' ' -f2 > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
