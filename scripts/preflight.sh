#!/usr/bin/env bash
# Is Mac signing available right now? Writes available=true|false to $GITHUB_OUTPUT.
#
# "No" means withdrawn, and it is not an error: a secret is missing, the certificate will not
# import or is out of date, or Apple rejects the API key's credentials. The job still
# succeeds, the workflow's `signing-withdrawn` job runs, and the source repository falls back
# to its unsigned Mac builds with a loud warning.
#
# Anything this script cannot classify (Apple unreachable, a bug here) is a failure of the
# job, which the source repository reads as a rejection. Withdrawal is something done
# on purpose; an outage is not allowed to look like it.
#
# Secrets come from the environment. Their names are reported, their values never.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib.sh
. "${ROOT}/scripts/lib.sh"

require_env GITHUB_OUTPUT
load_facts
forget_policy

setup_private_dir
trap cleanup_private EXIT

withdrawn() {
  echo "available=false" >>"${GITHUB_OUTPUT}"
  annotate warning "Mac signing is withdrawn: $1. The Mac builds will be unsigned."
  exit 0
}

missing=""
for name in MAC_CERT_P12 MAC_CERT_PASSWORD NOTARY_KEY NOTARY_KEY_ID NOTARY_ISSUER HALLMARK_RELEASE_TOKEN; do
  if [ -z "${!name:-}" ]; then
    missing="${missing} ${name}"
  fi
done
if [ -n "${missing}" ]; then
  withdrawn "these secrets are not set in the signing environment:${missing}"
fi

if ! import_cert; then
  withdrawn "${CERT_PROBLEM}"
fi

write_notary_key || withdrawn "the notarization key secret is not valid base64"

out="${PRIVATE_DIR}/history.json"
err="${PRIVATE_DIR}/history.err"
if notary history --output-format json >"${out}" 2>"${err}"; then
  echo "available=true" >>"${GITHUB_OUTPUT}"
  echo "Mac signing is available: certificate imported and in date, notarization key accepted."
  exit 0
fi

if grep -Eqi 'HTTP status code: 40[13]|invalid credentials|not authorized|unauthorized' "${err}"; then
  withdrawn "Apple does not accept the notarization key (revoked, expired or wrong IDs)"
fi

sed 's/^/notarytool: /' "${err}" | head -20 || true
die "the notarization service could not be checked (not a withdrawal: Apple may be unreachable)."
