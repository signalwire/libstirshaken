ARG DEBIAN_VERSION=trixie
FROM debian:${DEBIAN_VERSION}

LABEL org.opencontainers.image.authors="FreeSWITCH Solutions <packages@freeswitch.com>"
LABEL org.opencontainers.image.source="https://github.com/signalwire/libstirshaken"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libcurl4-openssl-dev \
        libssl-dev \
        libtool \
        pkgconf \
        uuid-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/signalwire/libks /usr/src/libs/libks \
    && cmake -S /usr/src/libs/libks -B /usr/src/libs/libks/build \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DWITH_LIBBACKTRACE=1 \
    && cmake --build /usr/src/libs/libks/build --parallel \
    && cmake --install /usr/src/libs/libks/build

RUN git clone --depth 1 https://github.com/akheron/jansson.git /usr/src/libs/jansson \
    && cd /usr/src/libs/jansson \
    && autoreconf -fi \
    && ./configure --prefix=/usr \
    && make -j"$(nproc)" \
    && make install

RUN git clone --depth 1 https://github.com/benmcollins/libjwt.git /usr/src/libs/libjwt \
    && cd /usr/src/libs/libjwt \
    && autoreconf -fi \
    && ./configure --prefix=/usr \
    && make -j"$(nproc)" \
    && make install

COPY . /usr/src/libstirshaken
WORKDIR /usr/src/libstirshaken

RUN ./bootstrap.sh \
    && ./configure --prefix=/usr \
    && make -j"$(nproc)" \
    && make check \
    && make install \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /usr/src/libs
