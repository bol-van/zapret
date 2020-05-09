FROM alpine:3.11

COPY binaries/x86_64/* /app

RUN ln -s /app/* /usr/bin

EXPOSE 8080/tcp

CMD tpws --bind-addr=0.0.0.0 --port=8080 --socks --split-pos=2 --hostspell hoSt --hostnospace
