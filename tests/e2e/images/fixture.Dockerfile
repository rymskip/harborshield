# Workload image for e2e containers: a banner server plus the probe client.
FROM alpine:3.24

RUN apk add --no-cache socat

COPY hs-serve hs-probe /usr/local/bin/

ENTRYPOINT ["hs-serve"]
