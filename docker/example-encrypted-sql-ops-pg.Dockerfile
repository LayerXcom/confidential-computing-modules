FROM anonify.azurecr.io/anonify-dev:latest

SHELL ["/bin/bash", "-c"]

ARG user_name=anonify-dev
ARG group_name=anonify-dev
COPY --chown=${user_name}:${group_name} . ${HOME}/anonify
WORKDIR ${HOME}/anonify

RUN cargo install cargo-pgx
RUN sudo apt-get update && \
    sudo apt-get install -y --no-install-recommends libreadline-dev
RUN cargo pgx init
