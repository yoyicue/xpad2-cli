#!/usr/bin/env bash
set -euo pipefail

umask 077

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BACKUP=${XPAD2_RELEASE_SIGNING_BACKUP:-}
PUBLIC_KEY="$ROOT/keys/catalog-release-public.pem"
EXPECTED_CERT_SHA256=3cb5b69579d23197ced8100818a85a46b821383a504b394a44cfe3e98ade78a2
EXPECTED_RECOVERY_FINGERPRINT=SHA256:cOVa4bIB0vgNbqR5Vi95Q0QFDLY7lJX79sHEHTm1Q2U

die() {
  printf 'XPAD2_CATALOG_SIGN_REFUSED reason=%s\n' "$1" >&2
  exit 1
}

[[ -n "$BACKUP" ]] || die signing-backup-not-set
KEYSTORE="$BACKUP/xpad2-boom-release.p12"
SECRET_FILE="$BACKUP/xpad2-boom-release-password.rsa-oaep-sha256"
RECOVERY_KEY="$BACKUP/recovery-rsa/id_rsa"
CERT="$BACKUP/xpad2-boom-release-cert.pem"

(($# == 2)) || die usage-input-catalog-output-signature
INPUT=$1
OUTPUT=$2

[[ -f "$INPUT" ]] || die catalog-missing
[[ -f "$BACKUP/SHA256SUMS" ]] || die backup-manifest-missing
[[ -f "$KEYSTORE" && -f "$SECRET_FILE" && -f "$RECOVERY_KEY" && -f "$CERT" ]] || \
  die signing-material-missing
[[ -f "$PUBLIC_KEY" ]] || die public-key-missing

(
  cd "$BACKUP"
  shasum -a 256 -c SHA256SUMS >/dev/null
) || die backup-checksum

cert_sha=$(openssl x509 -in "$CERT" -outform DER | shasum -a 256 | awk '{print $1}')
[[ "$cert_sha" == "$EXPECTED_CERT_SHA256" ]] || die certificate-mismatch
recovery_fingerprint=$(ssh-keygen -lf "$BACKUP/recovery-rsa/id_rsa.pub" | awk '{print $2}')
[[ "$recovery_fingerprint" == "$EXPECTED_RECOVERY_FINGERPRINT" ]] || \
  die recovery-key-mismatch

tmp_dir=$(mktemp -d /tmp/xpad2-catalog-sign.XXXXXX)
trap 'rm -rf "$tmp_dir"; unset XPAD2_SIGNING_PASSWORD' EXIT
cp "$RECOVERY_KEY" "$tmp_dir/recovery-key.pem"
chmod 600 "$tmp_dir/recovery-key.pem"
ssh-keygen -p -m PEM -P '' -N '' -f "$tmp_dir/recovery-key.pem" >/dev/null

XPAD2_SIGNING_PASSWORD=$(openssl pkeyutl -decrypt \
  -inkey "$tmp_dir/recovery-key.pem" \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 \
  -in "$SECRET_FILE")
export XPAD2_SIGNING_PASSWORD

if ! openssl pkcs12 -in "$KEYSTORE" -nocerts -nodes \
  -passin env:XPAD2_SIGNING_PASSWORD -out "$tmp_dir/private.pem" 2>/dev/null; then
  openssl pkcs12 -legacy -in "$KEYSTORE" -nocerts -nodes \
    -passin env:XPAD2_SIGNING_PASSWORD -out "$tmp_dir/private.pem" >/dev/null 2>&1 || \
    die pkcs12-open
fi
chmod 600 "$tmp_dir/private.pem"

openssl pkey -in "$tmp_dir/private.pem" -pubout -outform DER \
  -out "$tmp_dir/private-public.der" >/dev/null 2>&1
openssl pkey -pubin -in "$PUBLIC_KEY" -outform DER \
  -out "$tmp_dir/expected-public.der" >/dev/null 2>&1
cmp -s "$tmp_dir/private-public.der" "$tmp_dir/expected-public.der" || \
  die catalog-public-key-mismatch

mkdir -p "$(dirname "$OUTPUT")"
openssl dgst -sha256 -sign "$tmp_dir/private.pem" -out "$OUTPUT" "$INPUT"
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$OUTPUT" "$INPUT" \
  >/dev/null || die signature-self-check
chmod 600 "$OUTPUT"

unset XPAD2_SIGNING_PASSWORD
printf 'XPAD2_CATALOG_SIGN_OK catalog_sha256=%s signature_sha256=%s\n' \
  "$(shasum -a 256 "$INPUT" | awk '{print $1}')" \
  "$(shasum -a 256 "$OUTPUT" | awk '{print $1}')"
