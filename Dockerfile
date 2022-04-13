#
FROM python:3.10-slim-buster

ARG DEBIAN_FRONTEND=noninteractive

COPY requirements.txt /tmp

RUN apt-get update \
    && apt-get install -yqq libmagic1 git gcc \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && apt-get purge gcc git -yqq \
    && apt-get autoremove -yqq --purge \
    && apt-get clean -yqq \
    && rm -rf \
        /var/lib/apt/lists/* \
        /tmp/* \
        /var/tmp/* \
        /usr/share/man \
        /usr/share/doc \
        /usr/share/doc-base

COPY src/ /usr/local/bin/

WORKDIR /usr/local/bin
