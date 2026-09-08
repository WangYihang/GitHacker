FROM perl:5.38-slim

# The perl:5.38-slim image ships its own perl under /usr/local, while Debian's
# lib*-perl packages install into the system perl under /usr/share/perl5 — not
# on this interpreter's @INC. rip-git.pl died on "Can't locate LWP.pm" every
# run, so dvcs-ripper scored 0.0% across the matrix without ever starting.
# Install the modules into the interpreter that actually runs.
RUN apt-get update && apt-get install -y git curl build-essential zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cpanm --notest --quiet \
    LWP::UserAgent LWP::Protocol::https IO::Socket::SSL \
    IPC::Semaphore IPC::SharedMem
RUN git clone https://github.com/kost/dvcs-ripper.git /opt/dvcs-ripper

# Record version info (commit hash)
RUN cd /opt/dvcs-ripper && git rev-parse --short HEAD > /tool-version.txt

COPY run.sh /run.sh
RUN chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
