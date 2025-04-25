#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call \
  with-registry-auth \
    --address docker.io \
    --username $DOCKERHUB_USERNAME \
    --secret env:DOCKERHUB_TOKEN \
  build \
    --config ./tests/config/apko.yaml  \
    --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
  with-scan \
    --severity-cutoff critical \
  publish \
  digest

dagger call \
  with-registry-auth \
    --address docker.io \
    --username $DOCKERHUB_USERNAME \
    --secret env:DOCKERHUB_TOKEN \
  publish \
    --context ./tests  \
    --config ./tests/config/apko.yaml  \
    --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
  with-scan \
    --severity-cutoff critical \
  digest
