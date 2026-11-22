FROM ubuntu:26.04

ARG OPEN5GS_VERSION=2.8.0~resolute6

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates openssl procps software-properties-common \
    && add-apt-repository -y ppa:open5gs/latest \
    && apt-get update \
    && apt-get install -y --no-install-recommends "open5gs=${OPEN5GS_VERSION}" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY generate-certs.sh /usr/local/bin/generate-certs
RUN chmod 0755 /usr/local/bin/generate-certs
