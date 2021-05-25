# Root-less version of sgx-rust image.

FROM baiduxlab/sgx-rust:1804-1.1.3

RUN sudo rm -rf /root/*

# Create & switch to non-root user
ARG user_name=anonify-dev
ARG user_pass=anonify-dev
ARG user_id=61000
ARG group_name=anonify-dev
ARG group_id=61000

RUN groupadd -g ${group_id} ${group_name} && \
    useradd -g ${group_id} -G sudo -l -m -s /bin/bash -u ${user_id} ${user_name} && \
    echo "${user_name}:${user_pass}" | chpasswd && \
    echo "${user_name} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

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

# docker-compose's `volume:` mounts files as owned by different UID:GID than ${user_id}:${group_id} here.
# (Basically it mouts using host-side `UID:GID`)
# Chown home directory.
COPY --chown=${user_name}:${group_name} ./entrypoint/chown-home.sh ${HOME}
RUN chmod +x ${HOME}/chown-home.sh
## necessary to pass ARG to ENTRYPOINT
ENV user_name ${user_name}
ENV group_name ${group_name}
ENTRYPOINT ["sh", "-c", "${HOME}/chown-home.sh ${user_name} ${group_name}"]
