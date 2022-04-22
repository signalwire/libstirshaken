FROM debian:bullseye
MAINTAINER Andrey Volk <andrey@signalwire.com>

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -yq install git

RUN git clone https://github.com/signalwire/libstirshaken.git /usr/src/libstirshaken
RUN git clone https://github.com/signalwire/libks /usr/src/libs/libks
RUN git clone https://github.com/benmcollins/libjwt.git /usr/src/libs/libjwt
RUN git clone https://github.com/akheron/jansson.git /usr/src/libs/jansson

RUN DEBIAN_FRONTEND=noninteractive apt-get -yq install \
# build
    build-essential cmake automake autoconf 'libtool-bin|libtool' \
# general
    libssl-dev libcurl4-openssl-dev libjwt-dev uuid-dev pkgconf
  
RUN cd /usr/src/libs/libks && cmake . -DCMAKE_INSTALL_PREFIX=/usr -DWITH_LIBBACKTRACE=1 && make install
RUN cd /usr/src/libs/jansson && autoreconf -i && ./configure && make && make install
RUN cd /usr/src/libs/libjwt && autoreconf -i && ./configure && make && make install

RUN cd /usr/src/libstirshaken && ./bootstrap.sh
RUN cd /usr/src/libstirshaken && ./configure
RUN cd /usr/src/libstirshaken && make -j`nproc` && make install

# Cleanup the image
RUN apt-get clean

# Uncomment to cleanup even more
#RUN rm -rf /usr/src/*