#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  scan \
    --source ghcr.io/opopops/wolfi/bash:latest \
    --severity-cutoff high \
    --output-format table \
  contents

dagger call --progress=plain \
  scan-file \
    --source ./tests/files/test.file \
    --severity-cutoff high \
    --output-format table \
  contents