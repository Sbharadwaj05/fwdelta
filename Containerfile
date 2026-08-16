# Container image for the CI step in blueprint section 03.
#
# Works with podman or docker. The image exists so a pipeline can run the tool
# without a Rust toolchain; it is not the deployment story. That is the static
# musl binary this builds, which copies onto an isolated host on its own.
#
#   podman build -t fwdelta .
#   podman run --rm -v "$PWD:/work:ro" fwdelta \
#       diff --base /work/base.nft --head /work/head.nft
#
# The final stage is `scratch`: no shell, no package manager, no libc. There is
# nothing in the image except the binary, which is the same claim the static
# link makes, enforced by having nothing else to run.

FROM docker.io/library/rust:1.97.1-alpine AS build

# The toolchain is pinned in rust-toolchain.toml and the base image tag agrees
# with it. Both are stated so a third party can reproduce the digest.
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY . .

# --locked so the lockfile is the build input, not a suggestion. Path remapping
# keeps the build directory out of the binary, which is one of the things that
# otherwise makes two builds of identical source differ.
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="--remap-path-prefix=/src=. -C debuginfo=0"
RUN cargo build --release --locked --target x86_64-unknown-linux-musl -p fwdelta-cli

FROM scratch
COPY --from=build \
    /src/target/x86_64-unknown-linux-musl/release/fwdelta /fwdelta

# Documented so the image is self-describing to anyone who pulls it without the
# repository to hand.
LABEL org.opencontainers.image.title="fwdelta"
LABEL org.opencontainers.image.description="Semantic diff and formal reachability analysis for firewall policy"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/Sbharadwaj05/fwdelta"

ENTRYPOINT ["/fwdelta"]
