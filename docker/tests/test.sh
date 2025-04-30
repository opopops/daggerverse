#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  build \
    --context ./tests  \
    --file ./tests/files/Dockerfile \
    --platform linux/amd64,linux/arm64 \
  with-scan \
    --severity-cutoff critical \
  publish \
    --image ttl.sh/opopops-daggerverse-docker \
  ref
