#!/bin/sh

set -eu

missing_tools=''
for tool in docker trivy; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    missing_tools="$missing_tools $tool"
  fi
done

if [ -n "$missing_tools" ]; then
  echo "TOOL_UNAVAILABLE:${missing_tools}" >&2
  node verification/trivy-summary.mjs --tool-unavailable $missing_tools
  exit 2
fi

artifact_directory='.artifacts/security'
mkdir -p "$artifact_directory"
scan_status=0
blocking_status=0
build_revision=${GITHUB_SHA:-local}

if ! trivy fs \
  --scanners vuln,misconfig \
  --skip-dirs .artifacts \
  --skip-dirs .git \
  --skip-dirs apps/web/.next \
  --skip-dirs node_modules \
  --format json \
  --exit-code 0 \
  --output "$artifact_directory/filesystem.json" \
  .; then
  scan_status=1
fi

for application in api auth web worker; do
  image="kovcheg-$application:verification"
  if ! docker build \
    --file "apps/$application/Dockerfile" \
    --target runtime \
    --build-arg "BUILD_COMMIT_SHA=$build_revision" \
    --tag "$image" \
    .; then
    scan_status=1
    continue
  fi

  if ! trivy image \
    --scanners vuln \
    --format json \
    --exit-code 0 \
    --output "$artifact_directory/$application-image.json" \
    "$image"; then
    scan_status=1
  fi

  if ! trivy image \
    --format cyclonedx \
    --output "$artifact_directory/$application-sbom.cdx.json" \
    "$image"; then
    scan_status=1
  fi

  if ! trivy image \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --ignore-unfixed \
    --format json \
    --exit-code 1 \
    --output "$artifact_directory/$application-fixed-high-critical.json" \
    "$image"; then
    blocking_status=1
  fi
done

TRIVY_SCAN_STATUS=$scan_status TRIVY_BLOCKING_STATUS=$blocking_status \
  node verification/trivy-summary.mjs

if [ "$scan_status" -ne 0 ] || [ "$blocking_status" -ne 0 ]; then
  exit 1
fi
