# Root-less version of sgx-rust image.

FROM baiduxlab/sgx-rust:1804-1.1.3

RUN sudo rm -rf /root/*

COPY ./entrypoint/root-less.bash /root/
ENTRYPOINT ["bash", "-c", "/root/root-less.bash"]
