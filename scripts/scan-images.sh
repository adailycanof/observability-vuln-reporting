#!/usr/bin/env bash
# Scan every image listed in images.txt with Trivy and write one JSON report per
# image into reports/. Used by the scheduled workflow and runnable locally.
#   ./scripts/scan-images.sh [images.txt] [reports/]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

list=${1:-images.txt}
out=${2:-reports}
TRIVY_IMAGE=${TRIVY_IMAGE:-aquasec/trivy:0.76.2}
mkdir -p "$out"

run_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    trivy "$@"
  else
    docker run --rm -v "$PWD/$out:/out" -v trivy-cache:/root/.cache "$TRIVY_IMAGE" "$@"
  fi
}

status=0
while IFS= read -r image || [[ -n $image ]]; do
  image=${image%%#*}            # strip comments
  image=${image//[[:space:]]/}  # and whitespace
  [[ -z $image ]] && continue
  name=$(printf '%s' "$image" | tr '/:@' '___')
  if command -v trivy >/dev/null 2>&1; then dest="$out/$name.json"; else dest="/out/$name.json"; fi
  echo "scanning $image"
  if ! run_trivy image --quiet --scanners vuln --format json --output "$dest" "$image"; then
    echo "::warning::scan failed for $image"
    status=1
  fi
done <"$list"
exit "$status"
