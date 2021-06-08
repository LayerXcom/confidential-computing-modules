FROM anonify.azurecr.io/anonify-dev:latest

WORKDIR ${HOME}

RUN cargo install cargo-pgx
RUN sudo apt-get update && \
    sudo apt-get install -y --no-install-recommends libreadline-dev
RUN cargo pgx init

CMD ["bash"]