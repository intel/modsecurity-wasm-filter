FROM ubuntu:bionic
# basics
SHELL ["/bin/bash", "-c"] 
ARG http_proxy 
ARG https_proxy 
RUN apt-get update && apt-get install -y --no-install-recommends apt-utils ca-certificates \ 
    && apt-get autoremove -y \ 
    && apt-get clean \ 
    && apt-get install -y --no-install-recommends \
    software-properties-common apt-transport-https git wget curl pkg-config \
    autoconf autotools-dev automake libtool cmake python zlib1g-dev libpcre3 \
    libpcre3-dev gcc-7 g++-7 cpp-7 gcc python3 python3-distutils \
    && rm -rf /var/lib/apt/lists/* \
    && cd $HOME

ENV CC=gcc-7 
ENV CXX=g++-7
ENV CPP=cpp-7

WORKDIR /root
RUN git clone -b v3.9.1 https://github.com/protocolbuffers/protobuf \
    && cd protobuf \
    && git submodule update --init --recursive \
    && ./autogen.sh \
    && ./configure   \
    && make \
    && make check \
    && make install \
    && cd .. \
    && rm -rf protobuf

# Commit from SpiderLabs/ModSecurity repository, aiming at v3/dev/wasm-experimental branch
ARG MODSEC_SHA=a68a2c7199b680b09a1cb7b0197bc3a1889512d2

WORKDIR /root/
RUN git clone https://github.com/emscripten-core/emsdk.git -b 3.1.16 \ 
    && git clone https://github.com/M4tteoP/libpcre.git -b wasm-emscripten \
    && git clone https://github.com/SpiderLabs/ModSecurity.git \
    && git -C ModSecurity checkout $MODSEC_SHA \
    && git clone https://github.com/abseil/abseil-cpp -b 20211102.0 \
    && git clone https://github.com/proxy-wasm/proxy-wasm-cpp-sdk \
    && git clone https://github.com/istio/proxy.git -b 1.13.3

WORKDIR /root/emsdk
RUN ./emsdk install 3.1.16 \ 
    && ./emsdk activate 3.1.16 \
    && echo "source /root/emsdk/emsdk_env.sh" >> ~/.bashrc \  
    && cd ..

WORKDIR /root/libpcre
RUN autoreconf -ivf \
    && source "/root/emsdk/emsdk_env.sh" \
    && ./build_for_wasm.sh wasm32-emscripten \
    && mkdir /usr/local/pcre \
    && cp targets/wasm32-emscripten/*.a /usr/local/pcre \
    && cd .. 

WORKDIR /root/ModSecurity
RUN ./build.sh \
    && git submodule init && git submodule update \
    && autoreconf -ivf \
    && cd ~/emsdk \
    && source ./emsdk_env.sh \
    && cd ~/ModSecurity \
    && emconfigure ./configure --without-yajl --without-geoip --without-libxml --without-curl \
    --without-lua --disable-shared --disable-examples --disable-libtool-lock \
    --disable-debug-logs  --disable-mutex-on-pm --without-lmdb --without-maxmind \
    --without-ssdeep --without-pcre2 --with-pcre=./pcre-config \
    && emmake make -j 4 \
    && emmake make install \
    && cd ..

WORKDIR /root/proxy-wasm-cpp-sdk
RUN mkdir /build /sdk \
    && cp *.cc *.h *.js *.proto Makefile* *.a /sdk/ 

WORKDIR /root
RUN source "/root/emsdk/emsdk_env.sh" \
    && git clone https://github.com/protocolbuffers/protobuf -b v3.9.1 protobuf-wasm \
    && cd protobuf-wasm \
    && git clone https://github.com/kwonoj/protobuf-wasm wasm-patches \
    && cd wasm-patches \
    && git checkout 4bba8b2f38b5004f87489642b6ca4525ae72fe7f \
    && cd .. \
    && git apply wasm-patches/*.patch \
    && ./autogen.sh \
    && emconfigure ./configure --disable-shared CXXFLAGS="-O3 -flto" \
    && emmake make \
    && cd .. \
    && cp protobuf-wasm/src/.libs/libprotobuf-lite.a /sdk/libprotobuf-lite.a \
    && cp protobuf-wasm/src/.libs/libprotobuf.a /sdk/libprotobuf.a

WORKDIR /root 
RUN wget -O /usr/local/bin/bazel https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
    && chmod +x /usr/local/bin/bazel 

RUN mv proxy istio-proxy \
    && cd istio-proxy \ 
    && bazel build //extensions/common/wasm:json_util \ 
    && cp ~/istio-proxy/bazel-bin/extensions/common/wasm/nlohmann_json.hpp ~/istio-proxy/extensions/common/wasm/ \
    && cd ..

WORKDIR /root
ADD Makefile envoy-wasm-modsecurity-dynamic.cc utils.cc utils.h /build/ 

RUN cd ~/emsdk \
    && source ./emsdk_env.sh \
    && cd /build \
    && make 

FROM scratch
COPY --from=0 /build/envoy-wasm-modsecurity-dynamic.wasm /plugin.wasm
