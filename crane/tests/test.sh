#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  manifest \
    --image cgr.dev/chainguard/wolfi-base:latest

dagger call --progress=plain \
  manifest \
    --image cgr.dev/chainguard/wolfi-base:latest \
    --platform linux/amd64 \
  contents
