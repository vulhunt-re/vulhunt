FROM cgr.dev/chainguard/glibc-dynamic:latest-dev AS build

USER root

RUN apk update
RUN apk add rust cmake make build-base \
    git gmp-dev m4 bash

WORKDIR /build

COPY . .

RUN cargo install cargo-make && \
    cargo make build

RUN chown -R nonroot:nonroot target/release

FROM cgr.dev/chainguard/glibc-dynamic:latest AS runtime

LABEL org.opencontainers.image.source="https://github.com/binarly-io/vulhunt-ce"

COPY --from=build /build/target/release/vulhunt-ce /usr/local/bin/
COPY --from=build /build/target/release/bias-lutil /usr/local/bin/
COPY --from=build /build/target/release/bias-tutil /usr/local/bin/
COPY --from=build /build/target/release/sleighc /usr/local/bin/

ENTRYPOINT ["vulhunt-ce"]
