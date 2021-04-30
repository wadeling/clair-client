#!/usr/bin/env bash
#
# Build a static binary for the host OS/ARCH
#

echo "start"

export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# Override TARGET
TARGET="test"
SOURCE="./cmd"

echo "Building $TARGET"
go build -v -o "${TARGET}" -gcflags '-N -l' "${SOURCE}"


echo "Build end....."
