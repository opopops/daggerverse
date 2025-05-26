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
    --severity critical \
  publish \
    --tag ttl.sh/opopops/daggerverse/apko:24h \
  ref

dagger call --progress=plain \
  build \
    --config ./tests/config/apko.yaml  \
    --arch amd64,arm64 \
  with-scan \
    --severity critical \
  publish \
    --tag ttl.sh/opopops/daggerverse/apko:24h \
  ref

dagger call --progress=plain \
  --source ./tests  \
  publish \
    --config ./tests/config/apko.yaml  \
    --tag ttl.sh/opopops/daggerverse/apko:24h \
    --arch amd64,arm64 \
  with-scan \
    --severity critical \
  ref

if [[ -e "/var/run/docker.sock" ]]; then
  dagger call --progress=plain \
    with-unix-socket \
      --source /var/run/docker.sock \
    publish \
      --config ./tests/config/apko.yaml  \
      --tag daggerverse/apko:latest \
      --local \
    address
fi

if [[ -n "$DOCKERHUB_USERNAME" ]] && [[ -n "$DOCKERHUB_TOKEN" ]]; then
  dagger call --progress=plain \
    with-registry-auth \
      --username ${DOCKERHUB_USERNAME} \
      --secret env:DOCKERHUB_TOKEN \
      --address docker.io \
    build \
      --config ./tests/config/apko.yaml  \
      --arch amd64,arm64 \
    with-scan \
      --severity critical \
    publish \
      --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
    ref
fi
