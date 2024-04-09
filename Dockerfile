# Use Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04 as sgxbase

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    build-essential ocaml ocamlbuild automake autoconf libtool wget python3 libssl-dev git perl \
    libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake reprepro unzip pkgconf \
    libboost-dev libboost-system-dev libboost-thread-dev lsb-release libsystemd0 \
    python-is-python3 libpq-dev clang

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

RUN wget https://download.01.org/intel-sgx/sgx-linux/2.23/distro/ubuntu22.04-server/sgx_linux_x64_sdk_2.23.100.2.bin
RUN chmod +x sgx_linux_x64_sdk_2.23.100.2.bin

RUN ./sgx_linux_x64_sdk_2.23.100.2.bin --prefix /

ENV SGX_SDK=/sgxsdk
ENV PATH="${PATH}:${SGX_SDK}/bin:${SGX_SDK}/bin/x64"
ENV PKG_CONFIG_PATH="${SGX_SDK}/pkgconfig"
ENV LD_LIBRARY_PATH="${SGX_SDK}/sdk_libs"

RUN git clone https://github.com/jtv/libpqxx.git && cd libpqxx && git checkout 7.8.1 && \
    cd cmake && cmake .. && cmake --build . && cmake --install .

RUN git clone https://github.com/ssantos21/bc-crypto-base.git && cd bc-crypto-base && \
    ./configure && make && make install

RUN git clone https://github.com/ssantos21/bc-shamir.git && cd bc-shamir && \
    ./configure && make && make install

RUN git clone https://github.com/ssantos21/bc-bip39.git && cd bc-bip39 && \
    export CC="clang-14" && ./configure && make && make install

RUN rm sgx_linux_x64_sdk_2.23.100.2.bin && rm -rf libpqxx bc-crypto-base bc-shamir bc-bip39

COPY . /home/sss-sgx

WORKDIR /home/sss-sgx
RUN make SGX_MODE=SIM

ENTRYPOINT ["/home/sss-sgx/app"]