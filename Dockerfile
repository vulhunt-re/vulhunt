FROM cgr.dev/chainguard/glibc-dynamic:latest-dev AS build

USER root

RUN apk update
RUN apk add rust cmake make build-base \
    clang-20 llvm-20-dev git \
    bash curl xz zip

WORKDIR /build

COPY . .

RUN cargo install cargo-make && \
    cargo make --profile=release prepare-bundle

RUN chown -R nonroot:nonroot target/bundle

FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime

LABEL org.opencontainers.image.source="https://github.com/vulhunt-re/vulhunt"

USER root

COPY --from=build /usr/lib/libz.so.1 /usr/lib/libz.so.1

RUN ["/sbin/ldconfig", "/usr/lib"]

USER nonroot

WORKDIR /opt/vulhunt

ENV PATH="/opt/vulhunt:${PATH}"

COPY --from=build /build/target/bundle/vulhunt-ce /opt/vulhunt
COPY --from=build /build/target/bundle/bias-lutil /opt/vulhunt
COPY --from=build /build/target/bundle/bias-tutil /opt/vulhunt
COPY --from=build /build/target/bundle/sleighc /opt/vulhunt
COPY --from=build /build/target/bundle/lib /opt/vulhunt/lib

ENTRYPOINT ["vulhunt-ce"]
