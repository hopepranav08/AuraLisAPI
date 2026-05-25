# syntax=docker/dockerfile:1
# api-gateway Dockerfile — KrakenD 2.7
# KrakenD is a pre-built binary; we just copy the config file.
FROM devopsfaith/krakend:2.7

COPY krakend.json /etc/krakend/krakend.json

# Validate config at build time to catch errors early
RUN krakend check -d -c /etc/krakend/krakend.json

EXPOSE 8080
