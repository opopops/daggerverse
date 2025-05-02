#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  with-registry-auth \
    --username ${DOCKERHUB_USERNAME} \
    --secret env:DOCKERHUB_TOKEN \
    --address docker.io \
  with-package \
    --source ./tests/helm/daggerverse \
    --version "0.0.0" \
    --app-version "unstable" \
  push \
    --registry docker.io/opopops
