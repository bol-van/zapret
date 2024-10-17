ARG BUILDARCH=x86_64-musl

FROM messense/rust-musl-cross:$BUILDARCH

RUN <<'EOF'
    set -eu
    export PKG_CONFIG_PATH=$TARGET_HOME/lib/pkgconfig/
    export CC=$TARGET_CC

    mkdir /root/extlibs
    cd /root/extlibs

    apt update
    apt install --no-install-recommends -y wget libtool pkg-config libcap-dev

    wget https://www.zlib.net/zlib-1.3.1.tar.gz
    echo 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz | sha256sum -c && tar axf zlib-1.3.1.tar.gz

    git clone -b libnfnetlink-1.0.2 --depth 1 git://git.netfilter.org/libnfnetlink
    git clone -b libnetfilter_queue-1.0.5 --depth 1 git://git.netfilter.org/libnetfilter_queue
    git clone -b libmnl-1.0.5 --depth 1 git://git.netfilter.org/libmnl

    (
        cd zlib-*
        ./configure --static
        make -j$(nproc)
        make install
    )

    for i in libnfnetlink libmnl libnetfilter_queue; do
        (
            echo COMPILING $i
            cd $i
            ./autogen.sh
            ./configure --host=${TARGET_CC%-gcc} --prefix=$TARGET_HOME --enable-static
            make -j$(nproc)
            make install
        )
    done

    cp /usr/include/sys/capability.h ${TARGET_HOME}/include/sys/
    cp /usr/include/x86_64-linux-gnu/sys/queue.h ${TARGET_HOME}/include/sys/
EOF
