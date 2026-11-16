#!/usr/bin/env bash
# Installs the pinned gitleaks into ./.tools/bin after checking the release
# archive's sha256. A mismatch stops the install; nothing unverified runs.
set -euo pipefail
version=8.30.1
sha256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
dest=.tools/bin
url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --max-time 120 -o "$work/gitleaks.tar.gz" "$url"
echo "${sha256}  $work/gitleaks.tar.gz" | sha256sum -c --quiet -
mkdir -p "$dest"
tar -xzf "$work/gitleaks.tar.gz" -C "$work" gitleaks
install -m 0755 "$work/gitleaks" "$dest/gitleaks"
"$dest/gitleaks" version
