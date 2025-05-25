#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  with-keygen \
  build \
    --config ./tests/config/melange.yaml

dagger call --progress=plain \
  with-keygen \
  with-build \
    --config ./tests/config/melange.yaml \
  build \
    --config ./tests/config/melange.yaml

dagger call --progress=plain \
  with-keygen \
  build \
    --config ./tests/config/melange.yaml  \
    --arch amd64,arm64
