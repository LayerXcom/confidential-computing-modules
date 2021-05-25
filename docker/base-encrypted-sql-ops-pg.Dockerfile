FROM anonify.azurecr.io/anonify-dev:latest

SHELL ["/bin/bash", "-c"]

ARG user_name=anonify-dev
ARG group_name=anonify-dev
COPY --chown=${user_name}:${group_name} . ${HOME}/anonify
WORKDIR ${HOME}/anonify

RUN set -x && \
    cargo install cargo-pgx && \
    cargo pgx init
