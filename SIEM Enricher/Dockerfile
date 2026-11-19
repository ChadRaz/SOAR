# SIEM IP Enricher & Containment Simulator
#
#   docker build -t siem-enricher .
#   docker run --rm -it -v "$PWD/data:/data" siem-enricher            # interactive menu
#   docker run --rm -it -v "$PWD/data:/data" siem-enricher demo       # analyze a sample log (no key needed)
#   docker run --rm -it -v "$PWD/data:/data" siem-enricher test       # run the test suite
#
# Everything you want to keep (your logs, the firewall blocklist, the audit
# trail, a saved API key) lives in /data, which you mount from your computer.

ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="siem-enricher" \
      org.opencontainers.image.description="Enrich SIEM log IPs with VirusTotal and contain them on a simulated firewall"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    SIEM_OUT_DIR=/data/siem_output \
    SIEM_DOTENV=/data/.env \
    SIEM_NO_GUI=1 \
    USER=analyst

WORKDIR /app

# Dependencies first, so editing the script doesn't re-download them.
COPY requirements-dev.txt .
RUN python -m pip install -r requirements-dev.txt

COPY siem_enricher.py test_siem_enricher.py sample_siem.log docker-entrypoint.sh ./

# Strip Windows line endings from the entrypoint (a common cause of
# "exec /app/docker-entrypoint.sh: no such file or directory"), then create an
# unprivileged user and the /data folder it owns.
RUN sed -i 's/\r$//' docker-entrypoint.sh \
 && chmod 755 docker-entrypoint.sh \
 && useradd --create-home --uid 10001 --shell /bin/sh analyst \
 && mkdir -p /data \
 && chown analyst:analyst /data

USER analyst

# The build fails if any test fails, so a built image is a working image.
RUN python -m pytest -q -p no:cacheprovider /app/test_siem_enricher.py

WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["menu"]
