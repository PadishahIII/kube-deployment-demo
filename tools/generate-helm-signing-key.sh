#!/usr/bin/env bash
# Generate the GPG keypair used to sign the Helm chart (provenance).
#
# Run this ONCE to create the keypair, then:
#   1. Commit the PUBLIC key  -> resources/helm/webapp/keys/public.asc
#   2. Store the PRIVATE key (armored) as the Jenkins `helm-signing-key` File credential.
#
# CRITICAL: the key MUST have the SIGN usage flag. Helm 4 verifies provenance with
# ProtonMail/go-crypto's KeysByIdUsage(keyId, KeyFlagSign) — a key generated with only
# the `cert` (certify) flag is loaded but never matched, and `helm verify` fails with
# "signature made by unknown entity". `sign,cert` sets both flags (key flags 0x03).
set -euo pipefail

IDENTITY="kube-security chart signing <charts@devsecops.local>"
OUT_DIR="resources/helm/webapp/keys"
PUB_KEY="${OUT_DIR}/public.asc"

# Use a throwaway GNUPGHOME so we never touch the user's real keyring.
GNUPGHOME="$(mktemp -d)"; chmod 700 "${GNUPGHOME}"
trap 'rm -rf "${GNUPGHOME}"' EXIT

echo ">> generating ${IDENTITY} (rsa2048, usage: sign,cert)"
gpg --homedir "${GNUPGHOME}" --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key "${IDENTITY}" rsa2048 sign,cert

mkdir -p "${OUT_DIR}"
gpg --homedir "${GNUPGHOME}" --armor --export "charts@devsecops.local" > "${PUB_KEY}"
echo ">> public key written to ${PUB_KEY}"
echo "   fingerprint: $(gpg --homedir "${GNUPGHOME}" --with-colons --fingerprint "charts@devsecops.local" | awk -F: '/^fpr/{print $10}')"
echo "   key flags:   $(gpg --list-packets "${PUB_KEY}" | grep -oE 'key flags: [0-9]+')  (must include 2 = sign)"

echo
echo ">> PRIVATE key (armored) — store this as the Jenkins 'helm-signing-key' File credential:"
echo "   (do NOT commit it; it is the only secret in this flow)"
gpg --homedir "${GNUPGHOME}" --armor --export-secret-keys "charts@devsecops.local"
echo
echo "Done. Commit ${PUB_KEY}; add the private key above to Jenkins as 'helm-signing-key'."
