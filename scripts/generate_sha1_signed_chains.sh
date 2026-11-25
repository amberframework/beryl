#!/bin/sh
# Generates spec/vectors/beryl/sha1_signed_chains.pem: two certificate
# chains whose signatures use SHA-1, for the spec that checks Beryl refuses
# them by name (RFC 9155).
#
#   /bin/sh scripts/generate_sha1_signed_chains.sh /opt/homebrew/Cellar/openssl@4/4.1.0/bin/openssl
#
# The file holds, in order:
#   1. Beryl SHA-1 Test RSA Root           RSA-2048, self-signed with SHA-256
#   2. sha1-rsa.beryl.test                 leaf signed by (1) with sha1WithRSAEncryption
#   3. Beryl SHA-1 Test EC Root            P-256, self-signed with ECDSA-SHA-256
#   4. Beryl SHA-1 Test EC Intermediate    signed by (3) with ecdsa-with-SHA1
#   5. sha1-ec.beryl.test                  leaf signed by (4) with ECDSA-SHA-256
# Every certificate is valid from 2026-01-01 to 2046-01-01. The private keys
# live in a temporary directory and are deleted; only certificates are kept.
#
# The OpenSSL binary is pinned by version and sha256; any other binary
# stops the run. The new file's sha256 goes in spec/vectors/manifest.json.
set -eu

OPENSSL="${1:?usage: generate_sha1_signed_chains.sh /path/to/openssl}"
PINNED_VERSION="OpenSSL 4.1.0 23 Oct 2026 (Library: OpenSSL 4.1.0 23 Oct 2026)"
PINNED_SHA256="7687ff498451e22381f19ad10576f43257cdf9e4de5b9d219cfba5d7c9461526"

observed_version="$("$OPENSSL" version)"
observed_sha256="$(/usr/bin/shasum -a 256 "$OPENSSL" | cut -d ' ' -f 1)"
if [ "$observed_version" != "$PINNED_VERSION" ] || [ "$observed_sha256" != "$PINNED_SHA256" ]; then
  echo "openssl pin mismatch: '$observed_version' $observed_sha256" >&2
  echo "expected: '$PINNED_VERSION' $PINNED_SHA256" >&2
  exit 1
fi

REPOSITORY_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="$REPOSITORY_ROOT/spec/vectors/beryl/sha1_signed_chains.pem"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NOT_BEFORE=20260101000000Z
NOT_AFTER=20460101000000Z

cat > "$WORK/root.ext" <<'EXT'
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EXT
cat > "$WORK/intermediate.ext" <<'EXT'
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXT
leaf_extensions() {
  cat <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:$1
EXT
}

# issue NAME SUBJECT KEY_ALGORITHM_OPTIONS DIGEST ISSUER EXTENSIONS
# Writes $WORK/NAME.pem; ISSUER "self" means self-signed.
issue() {
  name="$1" subject="$2" key_options="$3" digest="$4" issuer="$5" extensions="$6"
  # shellcheck disable=SC2086
  "$OPENSSL" genpkey $key_options -out "$WORK/$name.key" 2>/dev/null
  "$OPENSSL" req -new -key "$WORK/$name.key" -subj "/CN=$subject" -out "$WORK/$name.csr"
  if [ "$issuer" = self ]; then
    "$OPENSSL" x509 -req -in "$WORK/$name.csr" -key "$WORK/$name.key" -"$digest" \
      -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -extfile "$extensions" -out "$WORK/$name.pem"
  else
    "$OPENSSL" x509 -req -in "$WORK/$name.csr" -CA "$WORK/$issuer.pem" -CAkey "$WORK/$issuer.key" -CAcreateserial \
      -"$digest" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -extfile "$extensions" -out "$WORK/$name.pem"
  fi
}

RSA="-algorithm RSA -pkeyopt rsa_keygen_bits:2048"
EC="-algorithm EC -pkeyopt ec_paramgen_curve:P-256"
leaf_extensions sha1-rsa.beryl.test > "$WORK/rsa_leaf.ext"
leaf_extensions sha1-ec.beryl.test > "$WORK/ec_leaf.ext"

issue rsa_root "Beryl SHA-1 Test RSA Root" "$RSA" sha256 self "$WORK/root.ext"
issue rsa_leaf sha1-rsa.beryl.test "$RSA" sha1 rsa_root "$WORK/rsa_leaf.ext"
issue ec_root "Beryl SHA-1 Test EC Root" "$EC" sha256 self "$WORK/root.ext"
issue ec_intermediate "Beryl SHA-1 Test EC Intermediate" "$EC" sha1 ec_root "$WORK/intermediate.ext"
issue ec_leaf sha1-ec.beryl.test "$EC" sha256 ec_intermediate "$WORK/ec_leaf.ext"

mkdir -p "$(dirname "$OUTPUT")"
cat "$WORK/rsa_root.pem" "$WORK/rsa_leaf.pem" "$WORK/ec_root.pem" "$WORK/ec_intermediate.pem" "$WORK/ec_leaf.pem" > "$OUTPUT"
/usr/bin/shasum -a 256 "$OUTPUT"
