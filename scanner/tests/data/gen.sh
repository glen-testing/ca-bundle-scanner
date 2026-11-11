#!/usr/bin/env bash
# Regenerate the OpenSSL-built test fixtures in this directory (needs OpenSSL 3).
# Every signature uses a throwaway test CA; compromised CAs contribute only public data.
set -euo pipefail
cd "$(dirname "$0")"
CERTS=../../certs/emudhra
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT

openssl x509 -inform DER -in "$CERTS/EM_DV_TLS_CA_G3B_emSign.der" -out "$T/target.pem"
openssl x509 -inform DER -in "$CERTS/emSign_ECC_Root_G3.der" -out "$T/g3.pem"

# Throwaway test CA and an unrelated clean certificate.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Scanner Test CA" \
  -days 36500 -keyout "$T/ca.key" -out testca.pem 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=clean.test" \
  -keyout "$T/leaf.key" -out "$T/leaf.csr" 2>/dev/null
openssl x509 -req -in "$T/leaf.csr" -CA testca.pem -CAkey "$T/ca.key" -days 36500 -out clean_leaf.pem 2>/dev/null

# C01: PKCS#7 bundles (target / clean) and passwordless PKCS#12 with plaintext cert bags.
openssl crl2pkcs7 -nocrl -certfile "$T/target.pem" -outform DER -out target.p7b
openssl crl2pkcs7 -nocrl -certfile clean_leaf.pem -outform DER -out clean.p7b
openssl pkcs12 -export -nokeys -in "$T/target.pem" -certpbe NONE -nomac -passout pass: -out target_nopass.p12
openssl pkcs12 -export -nokeys -in clean_leaf.pem -certpbe NONE -nomac -passout pass: -out clean_nopass.p12
# C13: password-protected PKCS#12 (certificate bag encrypted).
openssl pkcs12 -export -nokeys -in "$T/target.pem" -passout pass:secret -out target_encrypted.p12

# C06: a new certificate carrying the compromised CA's public key (signed by the test CA).
openssl x509 -in "$T/target.pem" -pubkey -noout > "$T/target_pub.pem"
openssl x509 -req -in "$T/leaf.csr" -force_pubkey "$T/target_pub.pem" -CA testca.pem -CAkey "$T/ca.key" \
  -days 36500 -set_serial 7 -out reissued_same_key.pem 2>/dev/null

# C30: a leaf whose AKI names the compromised CA (issuer = test CA forced to that SKI).
SKI=$(openssl x509 -in "$T/target.pem" -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' :')
printf 'subjectKeyIdentifier=%s\nbasicConstraints=critical,CA:TRUE\n' "$SKI" > "$T/fakeca.ext"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Fake issuer" \
  -keyout "$T/fake.key" -out "$T/fake.csr" 2>/dev/null
openssl x509 -req -in "$T/fake.csr" -signkey "$T/fake.key" -extfile "$T/fakeca.ext" -days 36500 -out "$T/fake.pem" 2>/dev/null
printf 'authorityKeyIdentifier=keyid:always\n' > "$T/leaf.ext"
openssl x509 -req -in "$T/leaf.csr" -CA "$T/fake.pem" -CAkey "$T/fake.key" -extfile "$T/leaf.ext" \
  -days 36500 -set_serial 9 -out leaf_issued_by_compromised.pem 2>/dev/null
openssl x509 -req -in "$T/leaf.csr" -CA testca.pem -CAkey "$T/ca.key" -extfile "$T/leaf.ext" \
  -days 36500 -set_serial 10 -out leaf_issued_by_testca.pem 2>/dev/null

# C10/C14: OpenSSL TRUSTED CERTIFICATE forms of the distrusted root.
openssl x509 -in "$T/g3.pem" -trustout -addtrust serverAuth -out trusted_g3_tls.pem
openssl x509 -in "$T/g3.pem" -trustout -addtrust emailProtection -out trusted_g3_email.pem
openssl x509 -in "$T/g3.pem" -trustout -addtrust serverAuth -addreject serverAuth -out trusted_g3_rejected.pem
openssl x509 -in clean_leaf.pem -trustout -addtrust serverAuth -out trusted_clean.pem

# C13: ZipCrypto-encrypted ZIP holding the target.
rm -f target_encrypted.zip && (cd "$T" && zip -q -P secret "$OLDPWD/target_encrypted.zip" target.pem)

# N15: ZIP entries compressed with LZMA (method 14, as in Source-engine .bsp map
# paks). The zip crate reads LZMA but cannot write it, so Python's zipfile does.
python3 -I -c 'import sys, zipfile
for src, out in zip(sys.argv[1::2], sys.argv[2::2]):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_LZMA) as z:
        z.write(src, "certs/ca.pem")' "$T/target.pem" lzma_target.zip clean_leaf.pem lzma_clean.zip

# C24: a certificate larger than 8 KiB (many SANs), for --cert / --fingerprint tests.
{ printf 'subjectAltName='; seq 1 600 | sed 's/.*/DNS:host&.big.test/' | paste -sd, -; } > "$T/big.ext"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=big.test" \
  -keyout "$T/big.key" -out "$T/big.csr" 2>/dev/null
openssl x509 -req -in "$T/big.csr" -CA testca.pem -CAkey "$T/ca.key" -extfile "$T/big.ext" \
  -days 36500 -set_serial 11 -out big_cert.pem 2>/dev/null
echo "fixtures regenerated"
