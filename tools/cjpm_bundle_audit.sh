#!/bin/sh

set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_DIR="$ROOT_DIR/target"
LOG_DIR="$TARGET_DIR/bundle-logs"
TMP_ROOT="${TMPDIR:-/tmp}"

PACKAGE_NAME="$(sed -n 's/^[[:space:]]*name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' cjpm.toml | head -n 1)"
PACKAGE_VERSION="$(sed -n 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' cjpm.toml | head -n 1)"

if [ -z "$PACKAGE_NAME" ] || [ -z "$PACKAGE_VERSION" ]; then
  echo "bundle-audit-failed: unable to read package name/version from cjpm.toml" >&2
  exit 2
fi

ARTIFACT_PATH="${1:-$TARGET_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.cjp}"
SHA_PATH="${2:-$ARTIFACT_PATH.sha256}"
MANIFEST_PATH="${3:-$LOG_DIR/$PACKAGE_NAME-$PACKAGE_VERSION.bundle-manifest.json}"
ARTIFACT_BASENAME="$(basename "$ARTIFACT_PATH")"
ARTIFACT_ROOT="$PACKAGE_NAME-$PACKAGE_VERSION/"

json_string_field() {
  field_name="$1"
  sed -n "s/^[[:space:]]*\"$field_name\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$MANIFEST_PATH" | head -n 1
}

json_raw_field() {
  field_name="$1"
  sed -n "s/^[[:space:]]*\"$field_name\"[[:space:]]*:[[:space:]]*\\([^,}][^,}]*\\).*/\\1/p" "$MANIFEST_PATH" | head -n 1 | tr -d ' '
}

compute_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi

  openssl dgst -sha256 "$1" | awk '{print $NF}'
}

require_entry() {
  entry_name="$1"
  if ! rg -x --fixed-strings "$entry_name" "$ENTRY_LIST_PATH" >/dev/null 2>&1; then
    echo "bundle-audit-failed: missing archive entry $entry_name" >&2
    exit 1
  fi
}

if [ ! -f "$ARTIFACT_PATH" ]; then
  echo "bundle-audit-failed: artifact not found: $ARTIFACT_PATH" >&2
  exit 1
fi

if [ ! -f "$SHA_PATH" ]; then
  echo "bundle-audit-failed: sha256 file not found: $SHA_PATH" >&2
  exit 1
fi

if [ ! -f "$MANIFEST_PATH" ]; then
  echo "bundle-audit-failed: manifest not found: $MANIFEST_PATH" >&2
  exit 1
fi

ENTRY_LIST_PATH="$(mktemp "$TMP_ROOT/jinguissl-bundle-audit-entries.XXXXXX.txt")"
SANITIZED_LOG_PATH="$(mktemp "$TMP_ROOT/jinguissl-bundle-audit-log.XXXXXX.txt")"
trap 'rm -f "$ENTRY_LIST_PATH" "$SANITIZED_LOG_PATH"' EXIT HUP INT TERM

tar -tf "$ARTIFACT_PATH" >"$ENTRY_LIST_PATH"

require_entry "$ARTIFACT_ROOT"
require_entry "${ARTIFACT_ROOT}cjpm.toml"
require_entry "${ARTIFACT_ROOT}README.md"
require_entry "${ARTIFACT_ROOT}src/jinguissl/jinguissl.cj"
require_entry "${ARTIFACT_ROOT}src/jinguissl/package.cj"
require_entry "${ARTIFACT_ROOT}src/jinguissl/contract/contract.cj"
require_entry "${ARTIFACT_ROOT}src/jinguissl/crypto/aes/aes.cj"
require_entry "${ARTIFACT_ROOT}src/jinguissl/crypto/tls/tls13.cj"
require_entry "${ARTIFACT_ROOT}src/jinguissl/crypto/ssh/ssh.cj"

ACTUAL_SHA256="$(compute_sha256 "$ARTIFACT_PATH")"
RECORDED_SHA256="$(awk '{print $1}' "$SHA_PATH")"

if [ "$ACTUAL_SHA256" != "$RECORDED_SHA256" ]; then
  echo "bundle-audit-failed: sha256 mismatch between artifact and $SHA_PATH" >&2
  echo "expected: $RECORDED_SHA256" >&2
  echo "actual:   $ACTUAL_SHA256" >&2
  exit 1
fi

MANIFEST_PACKAGE="$(json_string_field package)"
MANIFEST_VERSION="$(json_string_field version)"
MANIFEST_ARTIFACT="$(json_string_field artifact)"
MANIFEST_SHA256="$(json_string_field sha256)"
MANIFEST_LOG_PATH="$(json_string_field logPath)"
MANIFEST_BUNDLE_STATUS="$(json_raw_field bundleStatus)"
MANIFEST_WORKAROUND_APPLIED="$(json_raw_field workaroundApplied)"
MANIFEST_KNOWN_SHA_CRASH="$(json_raw_field knownUpstreamShaCrash)"

if [ "$MANIFEST_PACKAGE" != "$PACKAGE_NAME" ]; then
  echo "bundle-audit-failed: manifest package mismatch: $MANIFEST_PACKAGE" >&2
  exit 1
fi

if [ "$MANIFEST_VERSION" != "$PACKAGE_VERSION" ]; then
  echo "bundle-audit-failed: manifest version mismatch: $MANIFEST_VERSION" >&2
  exit 1
fi

if [ "$MANIFEST_ARTIFACT" != "$ARTIFACT_BASENAME" ]; then
  echo "bundle-audit-failed: manifest artifact mismatch: $MANIFEST_ARTIFACT" >&2
  exit 1
fi

if [ "$MANIFEST_SHA256" != "$ACTUAL_SHA256" ]; then
  echo "bundle-audit-failed: manifest sha256 mismatch" >&2
  exit 1
fi

if [ -z "$MANIFEST_BUNDLE_STATUS" ] || [ -z "$MANIFEST_WORKAROUND_APPLIED" ] || [ -z "$MANIFEST_KNOWN_SHA_CRASH" ]; then
  echo "bundle-audit-failed: manifest is missing bundle status flags" >&2
  exit 1
fi

LOG_PATH="$ROOT_DIR/$MANIFEST_LOG_PATH"
if [ ! -f "$LOG_PATH" ]; then
  echo "bundle-audit-failed: manifest logPath does not exist: $LOG_PATH" >&2
  exit 1
fi

perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' "$LOG_PATH" >"$SANITIZED_LOG_PATH"

if [ "$MANIFEST_KNOWN_SHA_CRASH" = "true" ]; then
  if [ "$MANIFEST_WORKAROUND_APPLIED" != "true" ]; then
    echo "bundle-audit-failed: known SHA crash should imply workaroundApplied=true" >&2
    exit 1
  fi
  if [ "$MANIFEST_BUNDLE_STATUS" = "0" ]; then
    echo "bundle-audit-failed: known SHA crash should not report bundleStatus=0" >&2
    exit 1
  fi
  if ! rg 'stdx\.crypto\.digest|SHA256|Abort trap: 6|ArtifactIndex::genFileCheckSum|libcrypto' "$SANITIZED_LOG_PATH" >/dev/null 2>&1; then
    echo "bundle-audit-failed: manifest says known SHA crash, but log markers are missing" >&2
    exit 1
  fi
else
  if [ "$MANIFEST_BUNDLE_STATUS" != "0" ]; then
    echo "bundle-audit-failed: bundleStatus is non-zero without a known SHA crash marker" >&2
    exit 1
  fi
fi

echo "bundle-audit-ok: $ARTIFACT_PATH"
echo "artifact_root: $ARTIFACT_ROOT"
echo "sha256: $ACTUAL_SHA256"
echo "manifest: $MANIFEST_PATH"
echo "log: $LOG_PATH"
echo "bundle_status: $MANIFEST_BUNDLE_STATUS"
echo "workaround_applied: $MANIFEST_WORKAROUND_APPLIED"
echo "known_upstream_sha_crash: $MANIFEST_KNOWN_SHA_CRASH"
