#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call \
    --registry-username $DOCKERHUB_USERNAME \
    --registry-password env:DOCKERHUB_TOKEN \
  build \
    --context ./tests  \
    --file ./tests/files/Dockerfile \
    --platform linux/amd64,linux/arm64 \
  with-scan \
    --severity-cutoff critical \
  publish \
    --image ${DOCKERHUB_USERNAME}/dagger-test:v1.0.0 \
  with-tag \
    --tag latest \
  ref
