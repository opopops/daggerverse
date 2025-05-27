#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  lint \
    --source ./tests/helm/daggerverse \
    --strict

dagger call --progress=plain \
  with-registry-auth \
    --username ${GITHUB_USERNAME} \
    --secret env:GITHUB_TOKEN \
    --address ghcr.io \
  with-package \
    --source ./tests/helm/daggerverse \
    --version "0.0.0" \
    --app-version "unstable" \
  push \
    --registry ghcr.io/${GITHUB_USERNAME}/test/helm
