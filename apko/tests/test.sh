#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  build \
    --config ./tests/config/apko.yaml  \
  with-scan \
    --severity-cutoff critical \
  publish \
    --tag ttl.sh/opopops/daggerverse/apko:24h \
  ref

dagger call --progress=plain \
  publish \
    --source ./tests  \
    --config ./tests/config/apko.yaml  \
    --tag ttl.sh/opopops/daggerverse/apko:24h \
    --arch amd64,arm64 \
  with-scan \
    --severity-cutoff critical \
  ref

dagger call --progress=plain \
  with-registry-auth \
    --username ${DOCKERHUB_USERNAME} \
    --secret env:DOCKERHUB_TOKEN \
    --address docker.io \
  build \
    --config ./tests/config/apko.yaml  \
    --arch amd64,arm64 \
  with-scan \
    --severity-cutoff critical \
  publish \
    --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
  ref
