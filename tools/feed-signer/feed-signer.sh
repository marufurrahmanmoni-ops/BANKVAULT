#!/usr/bin/env bash
# BANKVAULT threat-feed signer (ECDSA P-256 / SHA-256).
#
#   ./feed-signer.sh keygen <dir>          -> <dir>/feed-private.pem (KEEP OFFLINE), prints public key for build.gradle.kts
#   ./feed-signer.sh sign <private.pem> <threatdb.txt>   -> writes threatdb.txt.sig
#
# The app verifies with java.security.Signature("SHA256withECDSA") against the X.509 public key
# placed in app/build.gradle.kts (FEED_PUBLIC_KEY_X509_B64). Publish threatdb.txt and threatdb.txt.sig
# side by side over HTTPS and set the URL in BANKVAULT > More > Threat intelligence updates.
# Remember to increase the "version" line on every release (older versions are rejected).
set -euo pipefail
cmd=${1:-}
case "$cmd" in
  keygen)
    dir=${2:?dir}; mkdir -p "$dir"; umask 077
    openssl ecparam -name prime256v1 -genkey -noout -out "$dir/feed-private.pem"
    echo "FEED_PUBLIC_KEY_X509_B64 = $(openssl ec -in "$dir/feed-private.pem" -pubout -outform DER 2>/dev/null | base64 -w0)"
    ;;
  sign)
    key=${2:?private key}; body=${3:?threat db file}
    head -n1 "$body" | grep -qx 'BANKVAULT-THREATDB 1' || { echo "not a BANKVAULT threat db" >&2; exit 1; }
    openssl dgst -sha256 -sign "$key" "$body" | base64 -w0 > "$body.sig"
    echo "wrote $body.sig"
    ;;
  *) echo "usage: $0 keygen <dir> | sign <private.pem> <threatdb.txt>" >&2; exit 2 ;;
esac
