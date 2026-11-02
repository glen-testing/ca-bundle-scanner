#!/usr/bin/env bash
# Re-download the built-in certificates from crt.sh and check them against
# src/builtin.rs. Network access needed; not part of `cargo test`.
set -euo pipefail
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
grep -oE '\("[A-Za-z0-9_]+", cert!\("[^"]+"\), Role::[A-Za-z]+, "[0-9a-f]{64}"\)' src/builtin.rs |
while IFS= read -r line; do
  file=$(sed -E 's/.*cert!\("([^"]+)"\).*/\1/' <<<"$line")
  sha=$(sed -E 's/.*"([0-9a-f]{64})"\)$/\1/' <<<"$line")
  for try in 1 2 3 4 5; do
    curl -fsS "https://crt.sh/?d=$sha" -o "$T/c.pem" && break
    sleep $((try * 5))
  done
  got=$(openssl x509 -in "$T/c.pem" -outform DER | sha256sum | cut -c1-64)
  if [[ "$got" != "$sha" ]]; then echo "MISMATCH $file: crt.sh gave $got"; fail=1; continue; fi
  if ! cmp -s <(openssl x509 -in "$T/c.pem" -outform DER) "certs/emudhra/$file"; then
    echo "DIFFERS  $file (local copy does not match crt.sh)"; fail=1
  else
    echo "ok       $file"
  fi
done
exit $fail
