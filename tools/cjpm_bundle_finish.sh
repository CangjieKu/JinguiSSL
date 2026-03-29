#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_DIR="$ROOT_DIR/target"
LOG_DIR="$TARGET_DIR/bundle-logs"
TMP_ROOT="${TMPDIR:-/tmp}"
TMP_LOG_PATH="$(mktemp "$TMP_ROOT/jinguissl-cjpm-bundle.XXXXXX.log")"

PACKAGE_NAME="$(sed -n 's/^[[:space:]]*name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' cjpm.toml | head -n 1)"
PACKAGE_VERSION="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' cjpm.toml | head -n 1)"

if [ -z "$PACKAGE_NAME" ] || [ -z "$PACKAGE_VERSION" ]; then
  echo "failed: unable to read package name/version from cjpm.toml" >&2
  exit 2
fi

ARTIFACT_PATH="$TARGET_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.cjp"
TIMESTAMP="$(date '+%Y-%m-%dT%H:%M:%S%z')"
STAMP_SAFE="$(date '+%Y%m%d-%H%M%S')"
LOG_PATH="$LOG_DIR/cjpm-bundle-$STAMP_SAFE.log"
MANIFEST_PATH="$LOG_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.bundle-manifest.json"

set +e
cjpm bundle >"$TMP_LOG_PATH" 2>&1
bundle_status=$?
set -e

mkdir -p "$LOG_DIR"
cp "$TMP_LOG_PATH" "$LOG_PATH"
rm -f "$TMP_LOG_PATH"

artifact_ready=false
known_upstream_sha_bug=false

if [ -f "$ARTIFACT_PATH" ] && tar -tf "$ARTIFACT_PATH" >/dev/null 2>&1; then
  artifact_ready=true
fi

if [ "$artifact_ready" = true ] \
  && ! perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$LOG_PATH" | rg 'error: G\.' >/dev/null 2>&1 \
  && rg 'stdx\.crypto\.digest|ArtifactIndex::genFileCheckSum|genFileCheckSum' "$LOG_PATH" >/dev/null 2>&1
then
  known_upstream_sha_bug=true
fi

if [ "$bundle_status" -eq 0 ] || [ "$known_upstream_sha_bug" = true ]; then
  if command -v shasum >/dev/null 2>&1; then
    SHA256_VALUE="$(shasum -a 256 "$ARTIFACT_PATH" | awk '{print $1}')"
  else
    SHA256_VALUE="$(openssl dgst -sha256 "$ARTIFACT_PATH" | awk '{print $NF}')"
  fi

  printf '%s  %s\n' "$SHA256_VALUE" "$(basename "$ARTIFACT_PATH")" >"$ARTIFACT_PATH.sha256"
  cat >"$MANIFEST_PATH" <<EOF
{
  "package": "$PACKAGE_NAME",
  "version": "$PACKAGE_VERSION",
  "artifact": "$(basename "$ARTIFACT_PATH")",
  "sha256": "$SHA256_VALUE",
  "bundleStatus": $bundle_status,
  "workaroundApplied": $([ "$bundle_status" -eq 0 ] && printf 'false' || printf 'true'),
  "knownUpstreamShaCrash": $([ "$known_upstream_sha_bug" = true ] && printf 'true' || printf 'false'),
  "generatedAt": "$TIMESTAMP",
  "logPath": "${LOG_PATH#$ROOT_DIR/}"
}
EOF

  if [ "$bundle_status" -eq 0 ]; then
    echo "bundle-ok: $ARTIFACT_PATH"
    echo "sha256: $ARTIFACT_PATH.sha256"
    echo "manifest: $MANIFEST_PATH"
    exit 0
  fi

  echo "bundle-workaround-ok: cjpm bundle hit known SHA256 crash after producing a valid artifact"
  echo "artifact: $ARTIFACT_PATH"
  echo "sha256: $ARTIFACT_PATH.sha256"
  echo "manifest: $MANIFEST_PATH"
  echo "log: $LOG_PATH"
  exit 0
fi

echo "bundle-failed: no valid workaround path matched" >&2
echo "log: $LOG_PATH" >&2
tail -n 80 "$LOG_PATH" >&2 || true
exit "$bundle_status"
