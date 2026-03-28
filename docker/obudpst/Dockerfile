FROM alpine:3.22 AS build

RUN apk add --no-cache build-base cmake git

WORKDIR /src
RUN git clone --depth=1 https://github.com/BroadbandForum/obudpst.git .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build --target udpst -j"$(nproc)"

FROM alpine:3.22
RUN adduser -D -H -s /sbin/nologin udpst
COPY --from=build /src/build/udpst /usr/local/bin/udpst
USER udpst
EXPOSE 25000/udp
ENTRYPOINT ["/usr/local/bin/udpst"]
CMD ["-p", "25000"]
