#!/bin/bash

USER_ID=${HOST_UID:-61000}
GROUP_ID=${HOST_GID:-61000}
USER_NAME=${USER_NAME:-anonify-dev}
GROUP_NAME=${GROUP_NAME:-anonify-dev}
USER_PASS=${USER_PASS:-anonify-dev}

groupadd -g ${GROUP_ID} ${GROUP_NAME}
useradd -g ${GROUP_ID} -G sudo -l -m -s /bin/bash -u ${USER_ID} ${USER_NAME}
echo "${USER_NAME}:${USER_PASS}" | chpasswd
echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# in case docker volume mount creates home dir as root owner:
chown ${USER_NAME}:${GROUP_NAME} /home/${USER_NAME}

echo 'Moving rustup from root user. Wait for a while...'
mv /root/.cargo /home/${USER_NAME}/
mv /root/.rustup /home/${USER_NAME}/
chown ${USER_NAME}:${GROUP_NAME} -R /home/${USER_NAME}/.cargo
chown ${USER_NAME}:${GROUP_NAME} -R /home/${USER_NAME}/.rustup

cat <<EOS >> /home/${USER_NAME}/.bash_profile
# SGX SDK for the non-root user.
source /opt/sgxsdk/environment

# Rustup for the non-root user.
source ~/.cargo/env
EOS
chown ${USER_NAME}:${GROUP_NAME} /home/${USER_NAME}/.bash_profile

su - ${USER_NAME} --shell /bin/bash
