#
FROM python:3.10-slim-buster
LABEL maintainer="ss"

ARG DEBIAN_FRONTEND=noninteractive

COPY requirements.txt /tmp

RUN apt-get update \
    && apt-get install -yqq libmagic1 curl unzip \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && apt-get autoremove -yqq --purge \
    && apt-get clean -yqq \
    && curl -sL "https://github.com/mandiant/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip" -o /usr/local/bin/floss.zip \
    && unzip /usr/local/bin/floss.zip -d /usr/local/bin \
    && rm -rf \
        /var/lib/apt/lists/* \
        /tmp/* \
        /var/tmp/* \
        /usr/share/man \
        /usr/share/doc \
        /usr/share/doc-base

COPY src/ /usr/local/bin/

COPY docker-entrypoint.sh /

WORKDIR /usr/local/bin

ENTRYPOINT [ "/docker-entrypoint.sh" ]

