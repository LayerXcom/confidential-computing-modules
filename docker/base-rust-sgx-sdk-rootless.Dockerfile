# Root-less version of sgx-rust image.

FROM baiduxlab/sgx-rust:1804-1.1.3

RUN sudo rm -rf /root/*

# Create a non-root user
ARG user_name=anonify-dev
ARG user_pass=anonify-dev
ARG user_id=61000
ARG group_name=anonify-dev
ARG group_id=61000

RUN groupadd -g ${group_id} ${group_name} && \
    useradd -g ${group_id} -G sudo -l -m -s /bin/bash -u ${user_id} ${user_name} && \
    echo "${user_name}:${user_pass}" | chpasswd && \
    echo "${user_name} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Setup `fixuid` (https://github.com/boxboat/fixuid) to map host-side UID & GID with
# container-side ones.
# (Necessary to avoid permission errors on volume mount in Linux host)
RUN USER=${user_name} && \
    GROUP=${group_name} && \
    curl -SsL https://github.com/boxboat/fixuid/releases/download/v0.5/fixuid-0.5-linux-amd64.tar.gz | tar -C /usr/local/bin -xzf - && \
    chown root:root /usr/local/bin/fixuid && \
    chmod 4755 /usr/local/bin/fixuid && \
    mkdir -p /etc/fixuid && \
    printf "user: $USER\ngroup: $GROUP\npaths:\n  - /home/$USER\n  - /home/$USER/anonify" > /etc/fixuid/config.yml

# Switch to the non-root
USER ${user_name}
WORKDIR /home/${user_name}
ENV HOME /home/${user_name}

# Install SGX SDK for the non-root user.
# See: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/dockerfile/03_sdk.sh
RUN echo '. /opt/sgxsdk/environment' >> ~/.bashrc

# Install rust-toolchain for the non-root user.
# See: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/dockerfile/05_rust.sh
ARG rust_toolchain=nightly-2020-10-25
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${rust_toolchain}
RUN echo '. ~/.cargo/env' >> ~/.bashrc
ENV PATH $PATH:$HOME/.cargo/bin
RUN rustup component add rust-src rls rust-analysis clippy rustfmt && \
    cargo install xargo bindgen cargo-audit && \
    rm -rf ~/.cargo/registry && rm -rf ~/.cargo/git

COPY ./docker/entrypoint/fixuid.bash ./
ENTRYPOINT ["./fixuid.bash"]
CMD ["bash"]
