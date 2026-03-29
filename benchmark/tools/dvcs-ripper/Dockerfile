FROM perl:5.38-slim

RUN apt-get update && apt-get install -y git curl libio-socket-ssl-perl libdbd-sqlite3-perl libclass-dbi-perl libio-all-lwp-perl && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/kost/dvcs-ripper.git /opt/dvcs-ripper

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
