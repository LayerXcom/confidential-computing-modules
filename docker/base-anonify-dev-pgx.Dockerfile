FROM anonify.azurecr.io/anonify-dev:latest-test as builder

WORKDIR ${HOME}

RUN cargo install cargo-pgx
RUN sudo apt-get update && \
    sudo apt-get install -y --no-install-recommends libreadline-dev
RUN cargo pgx init
