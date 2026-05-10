FROM signalwire/freeswitch-public-base
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        autoconf \
        automake \
        clang-tools \
        libcurl4-openssl-dev \
        libjwt-dev \
        libks2 \
        libssl-dev \
        libtool \
        pkgconf \
        uuid-dev \
    && rm -rf /var/lib/apt/lists/*
COPY . /usr/local/src/libstirshaken
WORKDIR /usr/local/src/libstirshaken
