FROM python:3.12-slim

LABEL org.opencontainers.image.title="athena-mcp" \
      org.opencontainers.image.description="Athena: breaking-change and caller blast-radius analysis for git diffs" \
      org.opencontainers.image.source="https://github.com/aaryanrwt/athena" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Aaryan Rawat <aaryan28rwt@gmail.com>"

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE /build/
COPY src /build/src
RUN pip install --no-cache-dir /build && rm -rf /build

RUN useradd --create-home --uid 10001 athena
USER athena
WORKDIR /repo

# Mounted repositories are owned by another uid; allow git to read them.
RUN git config --global --add safe.directory '*'

ENTRYPOINT ["athena"]
CMD ["--help"]
