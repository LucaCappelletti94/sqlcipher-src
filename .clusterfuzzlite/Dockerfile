FROM gcr.io/oss-fuzz-base/base-builder-rust
# SQLCipher's OpenSSL provider needs OpenSSL 3, while the image's Ubuntu ships 1.1. cargo locates the sqlite-wasm-rs
# wrapper at the revision interop/web pins.
ARG OPENSSL_VERSION=3.5.8
ARG OPENSSL_SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config && \
    curl -sSfL -o /tmp/openssl.tar.gz \
        "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" && \
    echo "$OPENSSL_SHA256  /tmp/openssl.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/openssl.tar.gz -C /tmp && \
    cd "/tmp/openssl-$OPENSSL_VERSION" && \
    CFLAGS=-O2 ./Configure linux-x86_64 no-shared no-tests no-docs --prefix=/opt/openssl --libdir=lib && \
    make -j"$(nproc)" build_libs && \
    make install_dev && \
    rm -rf /tmp/openssl*
ENV PKG_CONFIG_PATH=/opt/openssl/lib/pkgconfig
COPY . $SRC/sqlcipher-src
WORKDIR $SRC/sqlcipher-src
ENV FUZZ_SQLCIPHER_SOURCES=/opt/sqlcipher-sources
RUN fuzz/sources.sh "$FUZZ_SQLCIPHER_SOURCES"
COPY .clusterfuzzlite/build.sh $SRC/
