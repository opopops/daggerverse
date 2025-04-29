#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  with-registry-auth \
    --address ghcr.io \
    --username $GITHUB_USERNAME \
    --secret env:GITHUB_TOKEN \
  with-registry-auth \
    --username $DOCKERHUB_USERNAME \
    --secret env:DOCKERHUB_TOKEN \
  build \
    --config ./tests/config/apko.yaml  \
    --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
    --arch amd64,arm64 \
  with-scan \
    --severity-cutoff critical \
  publish \
  ref

dagger call \
  with-registry-auth \
    --address ghcr.io \
    --username $GITHUB_USERNAME \
    --secret env:GITHUB_TOKEN \
  with-registry-auth \
    --username $DOCKERHUB_USERNAME \
    --secret env:DOCKERHUB_TOKEN \
  publish \
    --context ./tests  \
    --config ./tests/config/apko.yaml  \
    --tag docker.io/${DOCKERHUB_USERNAME}/private:apko \
    --arch amd64,arm64 \
  with-scan \
    --severity-cutoff critical \
  ref
