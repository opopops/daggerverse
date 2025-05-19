#!/usr/bin/env bash

#set -x
set -ueo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$MODULE_DIR"

dagger call --progress=plain \
  --source ./tests \
  build \
    --dockerfile files/Dockerfile \
    --platform linux/amd64,linux/arm64 \
  with-scan \
    --severity-cutoff critical \
  publish \
    --tag ttl.sh/opopops-daggerverse-docker \
  ref

if [[ -n "$DOCKERHUB_USERNAME" ]] && [[ -n "$DOCKERHUB_TOKEN" ]]; then
  dagger call --progress=plain \
    --source ./tests \
    with-registry-auth \
      --username ${DOCKERHUB_USERNAME} \
      --secret env:DOCKERHUB_TOKEN \
      --address docker.io \
    build \
      --dockerfile files/Dockerfile \
      --platform linux/amd64,linux/arm64 \
    with-scan \
      --severity-cutoff critical \
    publish \
      --tag docker.io/${DOCKERHUB_USERNAME}/private:docker \
    ref
fi
