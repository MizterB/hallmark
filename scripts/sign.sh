#!/usr/bin/env bash
# Sign, notarize and staple one Mac build (one leg of the matrix): the app, then the DMG.
#
# Inputs, all from the environment (the workflow sets them; nothing is interpolated into a
# shell command line):
#   HALLMARK_LEG          one of the builds the policy lists for the app
#   HALLMARK_VERIFIED     directory holding the verified files: <leg>/<app zip>, <leg>/dmg/*
#   HALLMARK_OUT          where the DMG and the leg's result file go
#   HALLMARK_POLICY, HALLMARK_SOURCE_REPO   the Team ID, file names and entitlements the policy
#                         sets for the app are read from these; the identity must match the Team ID
#   HALLMARK_REQUEST_ID   for the result file only
#   MAC_CERT_P12          the Developer ID Application certificate, .p12, base64
#   MAC_CERT_PASSWORD     its password
#   NOTARY_KEY            the App Store Connect API key (.p8 text, or base64 of it)
#   NOTARY_KEY_ID, NOTARY_ISSUER
#
# Failure anywhere is a rejection: the script exits non-zero and the workflow stops.
# Never add `set -x` here, and never echo a secret.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib.sh
. "${ROOT}/scripts/lib.sh"

# A command that fails under set -e would end the step with a bare exit code; this says why.
trap 'annotate error "signing stopped at line ${LINENO} of sign.sh."' ERR

require_env HALLMARK_LEG HALLMARK_VERIFIED HALLMARK_OUT HALLMARK_REQUEST_ID \
  MAC_CERT_P12 MAC_CERT_PASSWORD NOTARY_KEY NOTARY_KEY_ID NOTARY_ISSUER

[[ "${HALLMARK_LEG}" =~ ^[a-z0-9]{1,16}$ ]] || die "unknown build leg"
load_facts "${HALLMARK_LEG}"

setup_private_dir
trap cleanup_private EXIT

IN="${HALLMARK_VERIFIED}/${HALLMARK_LEG}"
mkdir -p "${HALLMARK_OUT}"
WORK="${PRIVATE_DIR}/work"
mkdir -p "${WORK}"

# Everything the policy says is read now; after this the policy text is dropped, because
# everything below runs tools over files the source repository supplied.
APP_ZIP="$(fact app_zip)"
ICON="$(fact icon)"
BACKGROUND="$(fact background)"
DMG_NAME="$(fact dmg_name)"
ENT="${PRIVATE_DIR}/entitlements"
python3 "${ROOT}/scripts/entitlements.py" write "${ENT}" || die "the entitlements the policy sets could not be written."
forget_policy

# ----------------------------------------------------------------- the vendored create-dmg

check_vendored_create_dmg() {
  local dir="${ROOT}/vendor/create-dmg" listed present
  (cd "${dir}" && shasum -a 256 -c CHECKSUMS.sha256 >/dev/null) ||
    die "the vendored create-dmg does not match its checksums."
  listed="$(wc -l <"${dir}/CHECKSUMS.sha256" | tr -d ' ')"
  present="$(find "${dir}" -type f ! -name CHECKSUMS.sha256 | wc -l | tr -d ' ')"
  [ "${listed}" = "${present}" ] || die "the vendored create-dmg holds files its checksum list does not name."
}

# ------------------------------------------------------------------------------ signing

sign_one() { # path [entitlements]
  if [ -n "${2:-}" ]; then
    codesign --force --timestamp --options runtime --sign "${IDENTITY}" --keychain "${KEYCHAIN}" \
      --entitlements "$2" "$1"
  else
    codesign --force --timestamp --options runtime --sign "${IDENTITY}" --keychain "${KEYCHAIN}" "$1"
  fi
}

team_of() {
  codesign -dv --verbose=4 "$1" 2>&1 | sed -n 's/^TeamIdentifier=//p'
}

# Submit a file, wait for the verdict, stop the build on anything but Accepted.
# Sets SUBMISSION_ID.
notarize() { # file label
  local out="${WORK}/notary-$2.json" err="${WORK}/notary-$2.err" status=""
  notary submit "$1" --wait --timeout 60m --output-format json >"${out}" 2>"${err}" || true
  SUBMISSION_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "${out}" 2>/dev/null || true)"
  status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "${out}" 2>/dev/null || true)"
  if ! [[ "${SUBMISSION_ID}" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    sed 's/^/notarytool: /' "${err}" | head -20 || true
    die "notarization of the $2 did not return a submission id."
  fi
  if [ "${status}" != "Accepted" ]; then
    echo "Apple's notarization log for submission ${SUBMISSION_ID}:"
    notary log "${SUBMISSION_ID}" || true
    die "Apple did not accept the $2 (status ${status:-unknown}, submission ${SUBMISSION_ID})."
  fi
  echo "notarized the $2: submission ${SUBMISSION_ID}"
}

echo "== certificate and key"
import_cert || die "${CERT_PROBLEM}."
write_notary_key || die "the notarization key secret is not valid base64."
# Nothing after this point needs the certificate or the key text, and everything below runs
# tools over files the source repository supplied, so they do not inherit them.
unset MAC_CERT_P12 MAC_CERT_PASSWORD NOTARY_KEY

APP_NAME="$(python3 "${ROOT}/scripts/layout.py" field "${IN}/dmg/layout.json" app_name)"
VOLNAME="$(python3 "${ROOT}/scripts/layout.py" field "${IN}/dmg/layout.json" volname)"

echo "== unpack the app"
APP_DIR="${WORK}/app"
mkdir -p "${APP_DIR}"
ditto -x -k "${IN}/${APP_ZIP}" "${APP_DIR}"
APP="${APP_DIR}/${APP_NAME}"
[ -d "${APP}" ] || die "the app zip does not hold ${APP_NAME}."
xattr -cr "${APP}"

echo "== sign inside-out (hardened runtime, timestamp)"
# Pairs of path and entitlements file, deepest first, the app itself last.
python3 "${ROOT}/scripts/sign_plan.py" "${APP}" "${ENT}/index.json" >"${WORK}/plan" || die "the app's nested code could not be listed."
PLAN=()
while IFS= read -r -d '' item; do PLAN+=("${item}"); done <"${WORK}/plan"
echo "code items to sign: $((${#PLAN[@]} / 2))"
i=0
while [ "${i}" -lt "${#PLAN[@]}" ]; do
  sign_one "${PLAN[i]}" "${PLAN[i + 1]}"
  i=$((i + 2))
done

echo "== verify the signature before sending it to Apple"
codesign --verify --strict --deep --verbose=2 "${APP}"
[ "$(team_of "${APP}")" = "${TEAM_ID}" ] || die "the app is signed by a different team than the policy pins."

echo "== notarize and staple the app"
ditto -c -k --keepParent "${APP}" "${WORK}/notarize-app.zip"
notarize "${WORK}/notarize-app.zip" "app"
APP_SUBMISSION="${SUBMISSION_ID}"
xcrun stapler staple "${APP}"
xcrun stapler validate "${APP}"
spctl -a -vv --type exec "${APP}"

echo "== build the DMG"
check_vendored_create_dmg
STAGE="${WORK}/dmgsrc"
mkdir -p "${STAGE}"
ditto "${APP}" "${STAGE}/${APP_NAME}"
python3 "${ROOT}/scripts/layout.py" args "${IN}/dmg/layout.json" "${IN}/dmg/${ICON}" "${IN}/dmg/${BACKGROUND}" >"${WORK}/dmg-args" || die "the DMG layout did not validate."
DMG_ARGS=()
while IFS= read -r -d '' arg; do DMG_ARGS+=("${arg}"); done <"${WORK}/dmg-args"
[ "${#DMG_ARGS[@]}" -gt 0 ] || die "the DMG layout did not validate."
DMG="${HALLMARK_OUT}/${DMG_NAME}"
rm -f "${DMG}"
bash "${ROOT}/vendor/create-dmg/create-dmg" "${DMG_ARGS[@]}" "${DMG}" "${STAGE}"
[ -f "${DMG}" ] || die "create-dmg did not produce a DMG."

echo "== sign, notarize and staple the DMG"
codesign --force --timestamp --sign "${IDENTITY}" --keychain "${KEYCHAIN}" "${DMG}"
notarize "${DMG}" "dmg"
DMG_SUBMISSION="${SUBMISSION_ID}"
xcrun stapler staple "${DMG}"
xcrun stapler validate "${DMG}"

echo "== final checks on the DMG"
codesign --verify --strict --verbose=2 "${DMG}"
spctl -a -vv --type open --context context:primary-signature "${DMG}"
[ "$(team_of "${DMG}")" = "${TEAM_ID}" ] || die "the DMG is signed by a different team than the policy pins."

SHA256="$(shasum -a 256 "${DMG}" | awk '{print $1}')"
cat >"${HALLMARK_OUT}/leg-${HALLMARK_LEG}.json" <<EOF
{
  "leg": "${HALLMARK_LEG}",
  "request_id": "${HALLMARK_REQUEST_ID}",
  "team_id": "${TEAM_ID}",
  "dmg": "${DMG_NAME}",
  "sha256": "${SHA256}",
  "app_submission_id": "${APP_SUBMISSION}",
  "dmg_submission_id": "${DMG_SUBMISSION}"
}
EOF
echo "signed ${HALLMARK_LEG}: ${SHA256}  (volume ${VOLNAME})"
