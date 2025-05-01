#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  build \
    --config ./tests/config/apko.yaml  \
    --tag ttl.sh/opopops/daggerverse-apko:1h \
  with-scan \
    --severity-cutoff critical \
  publish \
  ref

dagger call --progress=plain \
  publish \
    --source ./tests  \
    --config ./tests/config/apko.yaml  \
    --tag ttl.sh/opopops/daggerverse-apko:1h \
    --arch amd64,arm64 \
  with-scan \
    --severity-cutoff critical \
  ref
