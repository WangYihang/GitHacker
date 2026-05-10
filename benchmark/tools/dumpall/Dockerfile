FROM python:3.12-slim

RUN pip install --no-cache-dir dumpall

# Record version info
RUN pip show dumpall | grep -E '^Version:' | cut -d' ' -f2 > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
