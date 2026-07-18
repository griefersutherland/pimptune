#!/bin/bash
# bootstrap.sh — initialize step-ca with existing PKI for SCEPTune setup
set -euo pipefail

### Settings/variables

# Internal DNS name — matches container name and PIMPTUNE_STEP_API_URL
CA_HOST="stepca-clients"
CA_PORT=443

# CRL location, must match the CRL Path served by SCEPTune
CRL_URL="http://clients.pki.datalinknetworks.net/intermediate_ca.crl"
CRT_URL="http://clients.pki.datalinknetworks.net/intermediate_ca.crt"

# Certificate expiry info for issuing certs
MIN_TLS_DUR="24h"
MAX_TLS_DUR="720h"
DEF_TLS_DUR="${MAX_TLS_DUR}"

# Name for the provisioner user, "pimptune" is perfectly fine
PROVISIONER_NAME="pimptune"

# The folder containing all of the certificate and key files
INFO_SRC="./info"

# Directory mounted as /home/step inside the step-ca container
STEP_DIR="./ca"

# ################################################################################################
# THESE ARE THE FILES YOU NEED TO BRING:
# ################################################################################################
#
# - $INFO_SRC/root_ca.crt = the public cert for the root/trust anchor for this chain
#
# - $INFO_SRC/intermediate_ca.crt = the issuing CA for this scep server
# - $INFO_SRC/intermediate_ca.key = the encrypted private key for intermediate_ca.crt (RSA/ECC)
# - $INFO_SRC/intermediate_ca.txt = the plaintext password used to decrypt intermediate_ca.key
#
# - $INFO_SRC/scep_ra.crt = SCEP Registration Authority certificate (signed by intermediate CA)
# - $INFO_SRC/scep_ra.key = the encrypted private key for the scep_ra.crt (must be RSA type)
# - $INFO_SRC/scep_ra.txt = the plaintext password used to decrypt scep_ra.key
#
# - $INFO_SRC/pimptune.jwk.txt = the plaintext password used to encrypt a new JWK key
#
# ################################################################################################

ALL_FILES="root_ca.crt intermediate_ca.crt intermediate_ca.key intermediate_ca.txt scep_ra.crt scep_ra.key scep_ra.txt pimptune.jwk.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[.]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
error()   { echo -e "${RED}[!] ERROR:${RESET} $*"; }

verify_key() {
    local label="$1"
    local cert="$2"
    local key="$3"
    local password="$4"

    if ! openssl pkey -in "$key" -passin "pass:${password}" -noout 2>/dev/null; then
        if ! openssl ec -in "$key" -passin "pass:${password}" -noout 2>/dev/null; then
            error "Failed to decrypt key for ${label}"
            return 1
        fi
    fi

    # Verify cert and key are a matching pair by comparing public keys
    CERT_PUBKEY=$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null)
    KEY_PUBKEY=$(openssl pkey -in "$key" -passin "pass:${password}" -pubout 2>/dev/null) || \
    KEY_PUBKEY=$(openssl ec -in "$key" -passin "pass:${password}" -pubout 2>/dev/null)

    if [[ "$CERT_PUBKEY" != "$KEY_PUBKEY" ]]; then
        error "Key does not match certificate for ${label}"
        return 1
    fi

    success "Verified key/certificate: ${label}"
}

verify_signer() {
    local label="$1"
    local cert="$2"
    local issuer="$3"
    local root="$INFO_SRC/root_ca.crt"

    local tmpchain
    tmpchain=$(mktemp)

    if [[ "$cert" == "$root" ]]; then
        # Root self-signed — no untrusted intermediates needed
        openssl verify -CAfile "$root" "$root" > /dev/null 2>&1
    else
        # Build untrusted chain from issuer up to (but not including) root
        cat "$issuer" > "$tmpchain"
        openssl verify -CAfile "$root" -untrusted "$tmpchain" "$cert" > /dev/null 2>&1
    fi

    local rc=$?
    rm -f "$tmpchain"

    if [[ $rc -ne 0 ]]; then
        error "Signature verification failed for ${label}"
        return 1
    fi

    success "Validated signature: ${label}"
}

while getopts "f" opt; do
  case $opt in
    f)
      rm -rf "$STEP_DIR"
      ;;
    \?)
      error "Invalid option: -$OPTARG"
      ;;
  esac
done

# Sanity checks to ensure certificates exist
info "Verifying all required files"
if [[ -d "$STEP_DIR/config" ]]; then
    error "$STEP_DIR/config already exists. Use -f to remove $STEP_DIR and re-bootstrap."
    exit 1
fi

# Check all certificate and key files required for pimptune
for f in $ALL_FILES; do
    if [[ ! -f "$INFO_SRC/$f" ]]; then
        error "Missing required file: $INFO_SRC/$f"
        exit 1
    fi
done
success "All required files exist"
echo ""

# Read secrets and passwords, verify non-empty values
info "Verifying secret key values"
read -r CA_PASSWORD < "$INFO_SRC/intermediate_ca.txt"
if [[ -z "$CA_PASSWORD" ]]; then
    error "intermediate_ca.txt is empty"
    exit 1
fi
verify_key "Intermediate CA" "$INFO_SRC/intermediate_ca.crt" "$INFO_SRC/intermediate_ca.key" "$CA_PASSWORD"

read -r RA_PASSWORD < "$INFO_SRC/scep_ra.txt"
if [[ -z "$RA_PASSWORD" ]]; then
    error "scep_ra.txt is empty"
    exit 1
fi
verify_key "SCEP RA" "$INFO_SRC/scep_ra.crt" "$INFO_SRC/scep_ra.key" "$RA_PASSWORD"

read -r JWK_PASSWORD < "$INFO_SRC/pimptune.jwk.txt"
if [[ -z "$JWK_PASSWORD" ]]; then
    error "pimptune.jwk.txt is empty"
    exit 1
fi
success "All secret key values verified"
echo ""

info "Verifying certificate chain"
verify_signer "Root CA (Self-Signed)" "$INFO_SRC/root_ca.crt" "$INFO_SRC/root_ca.crt"
verify_signer "Intermediate CA" "$INFO_SRC/intermediate_ca.crt" "$INFO_SRC/root_ca.crt"
verify_signer "SCEP RA" "$INFO_SRC/scep_ra.crt" "$INFO_SRC/intermediate_ca.crt"
success "All certificates verified"
echo ""

# Create directory structure for step-ca
info "Creating and initializing step-ca"
mkdir -p "$STEP_DIR/certs" "$STEP_DIR/secrets" "$STEP_DIR/config" "$STEP_DIR/db" "$STEP_DIR/templates/certs"

# Write password files (step-ca reads these at startup to decrypt keys) and set perms
echo -n "$CA_PASSWORD"  > "$STEP_DIR/secrets/password"
chmod 600 "$STEP_DIR/secrets/password"
echo -n "$RA_PASSWORD"  > "$STEP_DIR/secrets/scep_ra.txt"
chmod 600 "$STEP_DIR/secrets/scep_ra.txt"
echo -n "$JWK_PASSWORD" > "$STEP_DIR/secrets/pimptune.jwk.txt"
chmod 600 "$STEP_DIR/secrets/pimptune.jwk.txt"

# Run step ca init to generate boilerplate config
# Using internal container name as DNS — step-ca never needs to be externally reachable
INIT_OUTPUT=$(docker run --rm \
    -v "$(pwd)/$STEP_DIR:/home/step" \
    smallstep/step-ca \
    step ca init \
        --name "temporary" \
        --dns "$CA_HOST" \
        --address ":$CA_PORT" \
        --provisioner "$PROVISIONER_NAME" \
        --provisioner-password-file /home/step/secrets/pimptune.jwk.txt \
        --password-file /home/step/secrets/password \
    2>&1)
if [[ $? -ne 0 ]]; then
    error "step ca init failed:"
    echo "$INIT_OUTPUT"
    exit 1
fi
success "Completed step-ca initialization"
echo ""

info "Installing PKI artifacts and creating configuration"
cp "$INFO_SRC/root_ca.crt"         "$STEP_DIR/certs/root_ca.crt"
cp "$INFO_SRC/intermediate_ca.crt" "$STEP_DIR/certs/intermediate_ca.crt"
cp "$INFO_SRC/intermediate_ca.key" "$STEP_DIR/secrets/intermediate_ca_key"
cp "$INFO_SRC/scep_ra.crt"         "$STEP_DIR/certs/scep_ra.crt"
cp "$INFO_SRC/scep_ra.key"         "$STEP_DIR/secrets/scep_ra_key"
{ cat "$INFO_SRC/intermediate_ca.crt"; echo; cat "$INFO_SRC/root_ca.crt"; } | sed '/^$/d' > "$STEP_DIR/certs/full_chain.pem"
chmod 600 "$STEP_DIR/secrets/intermediate_ca_key"
chmod 600 "$STEP_DIR/secrets/scep_ra_key"

ENCRYPTED_JWK=$(jq -r ".authority.provisioners[] | select(.name == \"${PROVISIONER_NAME}\") | .encryptedKey" "$STEP_DIR/config/ca.json")

if [[ -z "$ENCRYPTED_JWK" || "$ENCRYPTED_JWK" == "null" ]]; then
    error "Could not extract encryptedKey for pimptune provisioner from ca.json"
    exit 1
fi

echo -n "$ENCRYPTED_JWK" > "$STEP_DIR/secrets/pimptune.jwk"
chmod 600 "$STEP_DIR/secrets/pimptune.jwk"

# Remove the auto-generated root key, it has no place here
rm -f "$STEP_DIR/secrets/root_ca_key"

# Compute fingerprint of YOUR root cert
FINGERPRINT=$(docker run --rm \
    -v "$(pwd)/$STEP_DIR:/home/step" \
    smallstep/step-ca \
    step certificate fingerprint /home/step/certs/root_ca.crt)
success "Root CA fingerprint: $FINGERPRINT"

# Rewrite defaults.json with correct fingerprint and internal URL
cat > "$STEP_DIR/config/defaults.json" <<EOF
{
    "ca-url": "https://${CA_HOST}:${CA_PORT}",
    "ca-config": "/home/step/config/ca.json",
    "fingerprint": "${FINGERPRINT}",
    "root": "/home/step/certs/root_ca.crt"
}
EOF

jq --arg crlURL "$CRL_URL" '
    .crl = {
        "enabled": true,
        "generateOnRevoke": true,
        "idpURL": $crlURL,
        "cacheDuration": "24h",
        "renewPeriod": "16h"
    }
' "$STEP_DIR/config/ca.json" > "$STEP_DIR/config/ca.json.tmp" \
    && mv "$STEP_DIR/config/ca.json.tmp" "$STEP_DIR/config/ca.json" \
    || { error "Failed to patch CRL config into ca.json"; exit 1; }

jq --arg name "$PROVISIONER_NAME" \
   --arg minDur "$MIN_TLS_DUR" \
   --arg maxDur "$MAX_TLS_DUR" \
   --arg defDur "$DEF_TLS_DUR" \
   '(.authority.provisioners[] | select(.name == $name)).claims = {
        "minTLSCertDuration": $minDur,
        "maxTLSCertDuration": $maxDur,
        "defaultTLSCertDuration": $defDur,
        "disableRenewal": false,
        "allowRenewalAfterExpiry": false,
        "disableSmallstepExtensions": false
    }' "$STEP_DIR/config/ca.json" > "$STEP_DIR/config/ca.json.tmp" \
    && mv "$STEP_DIR/config/ca.json.tmp" "$STEP_DIR/config/ca.json" \
    || { error "Failed to patch provisioner claims into ca.json"; exit 1; }

jq \
    --arg tplFile "templates/certs/pimptune.tpl" \
    --arg crlURL "$CRL_URL" \
    --arg crtURL "$CRT_URL" \
    '(.authority.provisioners[] | select(.name == "pimptune")).options = {
        "x509": {
            "templateFile": $tplFile,
            "templateData": {
                "CRLURL": $crlURL,
                "CRTURL": $crtURL
            }
        }
    }
' "$STEP_DIR/config/ca.json" > "$STEP_DIR/config/ca.json.tmp" \
    && mv "$STEP_DIR/config/ca.json.tmp" "$STEP_DIR/config/ca.json" \
    || { error "Failed to patch provisioner template into ca.json"; exit 1; }

cat > "$STEP_DIR/templates/certs/pimptune.tpl" <<EOF
{
    "subject": {{ toJson .Insecure.CR.Subject }},
    "extensions": {{ toJson .Insecure.CR.Extensions }},
    "basicConstraints": { "isCA": false },
    "crlDistributionPoints": ["${CRL_URL}"],
    "issuingCertificateURL": ["${CRT_URL}"]
}
EOF

STEPCA_UID=1000
PIMPTUNE_UID=65532

sudo chown "$STEPCA_UID" \
    "$STEP_DIR/secrets/intermediate_ca_key" \
    "$STEP_DIR/secrets/password" \
    "$STEP_DIR/templates/certs/pimptune.tpl"

sudo chown "$PIMPTUNE_UID" \
    "$STEP_DIR/secrets/scep_ra.txt" \
    "$STEP_DIR/secrets/scep_ra_key" \
    "$STEP_DIR/secrets/pimptune.jwk" \
    "$STEP_DIR/secrets/pimptune.jwk.txt"

success "Files installed, configuration created, CRLs enabled, and environment cleaned"
echo ""

echo -e "${BOLD}${GREEN}####################################${RESET}"
echo -e "${BOLD}${GREEN}#   SCEPTune Bootstrap complete!   #${RESET}"
echo -e "${BOLD}${GREEN}####################################${RESET}"
echo ""