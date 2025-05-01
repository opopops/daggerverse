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
  package-push \
    --source ./tests/helm/daggerverse  \
    --registry docker.io/opopops \
    --version "0.0.0" \
    --app-version "unstable"
