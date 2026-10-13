# Sandbox for running generated Jazzer.js harnesses.
# Run with: --network none --memory 2g --cpus 2 --read-only (target mounted at /work)
FROM node:20-slim

RUN npm install -g @jazzer.js/core && npm cache clean --force

RUN useradd --create-home fuzzer
USER fuzzer
WORKDIR /work
