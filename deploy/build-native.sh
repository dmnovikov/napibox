#!/usr/bin/env bash
set -euo pipefail
umask 077

stage=${1:?staging directory required}
version=${2:?Go version required}
checksum=${3:?Go archive SHA256 required}
cd "$stage"
test "$(uname -m)" = x86_64
archive="$version.linux-amd64.tar.gz"
curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 \
  "https://go.dev/dl/$archive" -o "$archive"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check -
mkdir toolchain src
tar -xzf "$archive" -C toolchain
tar -xzf source.tar.gz -C src
export GOCACHE="$stage/go-cache" GOPATH="$stage/go-path"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off GOENV=off
go_bin="$stage/toolchain/go/bin/go"
"$go_bin" version
cd src
"$go_bin" test ./...
"$go_bin" vet ./...
if command -v gcc >/dev/null 2>&1; then "$go_bin" test -race ./...; fi
CGO_ENABLED=0 "$go_bin" build -buildvcs=false -trimpath -ldflags='-s -w' -o "$stage/napibox" .
"$go_bin" version -m "$stage/napibox"
sha256sum "$stage/napibox"
