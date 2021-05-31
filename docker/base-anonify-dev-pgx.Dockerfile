FROM anonify.azurecr.io/anonify-dev:latest-test as builder

WORKDIR ${HOME}

# Old version of Rust (defined in `base-rust-sgx-sdk-rootless`) cannot compile pgx project,
# although newer version of Rust cannot build SGX SDK (what a hell).
RUN rustup default nightly-2021-05-18

RUN cargo install cargo-pgx
RUN sudo apt-get update && \
    sudo apt-get install -y --no-install-recommends libreadline-dev
RUN cargo pgx init
