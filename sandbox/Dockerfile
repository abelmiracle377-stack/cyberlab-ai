FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends nodejs bash ca-certificates && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 sandbox && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin sandbox
WORKDIR /workspace
USER 10001:10001
ENV HOME=/tmp LANG=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT []
