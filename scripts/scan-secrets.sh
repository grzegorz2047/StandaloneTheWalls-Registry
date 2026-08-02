#!/usr/bin/env bash
set -euo pipefail
if grep -RInE --exclude-dir=.git --exclude-dir=.gradle --exclude-dir=build --exclude=gradle-wrapper.jar --exclude=scan-secrets.sh \
  '(BEGIN (OPENSSH |EC |RSA |ED25519 )?PRIVATE KEY|recovery (phrase|seed)|mnemonic)' .; then
  echo "private key or recovery material detected" >&2
  exit 1
fi
