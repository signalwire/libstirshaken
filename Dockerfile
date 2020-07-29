FROM signalwire/freeswitch-public-base
RUN apt-get update && apt-get install -y clang-tools-7 libjansson-dev libcjson-dev libcurl-ocaml-dev libjwt-dev uuid-dev
COPY . /usr/local/src/libstirshaken
WORKDIR /usr/local/src/libstirshaken

