# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/wolfi-base:latest

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

RUN apk add --no-cache \
    curl
