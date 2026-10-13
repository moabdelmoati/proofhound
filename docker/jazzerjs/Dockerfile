# Sandbox for running generated Jazzer.js harnesses.
# Fuzzing runs use: --network none --memory 2g --cpus 2 --pids-limit 256
#   /work/target  target package (read-only, dependencies already installed)
#   /work/out     harness, corpus, crash files, coverage (writable)
# Jazzer.js 4 prebuilt binaries need glibc >= 2.38 (Debian trixie).
FROM node:22-trixie-slim

ARG JAZZER_VERSION=4.0.0
# A local (flat) install, not `npm i -g`: Jazzer.js resolves its bug detectors as sibling packages.
WORKDIR /opt/jazzer
RUN npm init -y >/dev/null && npm install @jazzer.js/core@${JAZZER_VERSION} && npm cache clean --force

# Let harnesses `require("@jazzer.js/core")` from any directory.
ENV NODE_PATH=/opt/jazzer/node_modules
ENV PATH=/opt/jazzer/node_modules/.bin:$PATH

RUN useradd --create-home fuzzer
USER fuzzer
WORKDIR /work/out
