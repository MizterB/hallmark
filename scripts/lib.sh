#!/usr/bin/env bash
# Shared by preflight.sh and sign.sh. Sourced, not run.
#
# Rules this file keeps:
#   - never `set -x`, never echo a secret; secrets arrive in the environment only
#   - everything private lives under one directory made with umask 077 and removed on exit
#   - every annotation ends with the standard disable sentence

DISABLE_SENTENCE='To skip Mac signing set the repository variable MAC_SIGNING to 0; to remove it permanently follow the "Remove Mac signing" runbook.'

annotate() {
  local level="$1"
  shift
  local msg="$* ${DISABLE_SENTENCE}"
  # bash 3.2 (macOS) keeps quotes inside the replacement, so the pieces are variables.
  local pct='%25' cr='%0D' lf='%0A' raw_cr=$'\r' raw_lf=$'\n'
  msg="${msg//%/${pct}}"
  msg="${msg//${raw_cr}/${cr}}"
  msg="${msg//${raw_lf}/${lf}}"
  echo "::${level} title=Mac signing::${msg}"
}

# require_env NAME...  stops with the standard sentence when one is empty or unset.
require_env() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      die "the step was started without ${name}."
    fi
  done
}

die() {
  annotate error "$*"
  exit 1
}

# Reads what the policy says about HALLMARK_SOURCE_REPO (and the build named by the optional
# argument) into a private file, then sets TEAM_ID. The policy is read here rather than
# passed in, so no step prints any of it. `fact KEY` prints one value afterwards.
FACTS=""
load_facts() { # [build]
  require_env HALLMARK_POLICY HALLMARK_SOURCE_REPO
  local dir
  umask 077
  dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hallmark-facts-$$"
  mkdir -p "${dir}"
  FACTS="${dir}/facts.json"
  python3 "$(dirname "${BASH_SOURCE[0]}")/policy.py" facts "${HALLMARK_SOURCE_REPO}" "${FACTS}" ${1:+"$1"} ||
    die "the policy gives no usable entry for this request."
  TEAM_ID="$(fact team_id)"
  [[ "${TEAM_ID}" =~ ^[A-Z0-9]{10}$ ]] || die "the policy's Team ID is malformed."
}

# fact KEY: a text value, or one line per item for a list.
fact() {
  python3 -c '
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]
print("\n".join(value) if isinstance(value, list) else value)
' "${FACTS}" "$1"
}

# Drop the policy text and the facts file once nothing else needs them.
forget_policy() {
  unset HALLMARK_POLICY
  [ -n "${FACTS}" ] && rm -rf "$(dirname "${FACTS}")"
  FACTS=""
}

# Where private files go. The keychain has a fixed name so the workflow's always() step can
# delete it even if this script died early.
setup_private_dir() {
  umask 077
  LEG_TAG="${HALLMARK_LEG:-preflight}"
  PRIVATE_DIR="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/hallmark-${LEG_TAG}"
  rm -rf "${PRIVATE_DIR}"
  mkdir -p "${PRIVATE_DIR}"
  KEYCHAIN="${PRIVATE_DIR}/signing.keychain-db"
}

cleanup_private() {
  if [ -n "${KEYCHAIN:-}" ] && [ -e "${KEYCHAIN}" ]; then
    security delete-keychain "${KEYCHAIN}" >/dev/null 2>&1 || true
  fi
  if [ -n "${PRIVATE_DIR:-}" ]; then
    rm -rf "${PRIVATE_DIR}"
  fi
}

# Import the certificate into a throwaway keychain and find its identity.
# Sets IDENTITY (the SHA-1 of the one Developer ID Application identity for TEAM_ID).
# Returns 1 with CERT_PROBLEM set when the certificate cannot be used.
import_cert() {
  CERT_PROBLEM=""
  local kc_pass p12
  # Only the certificate itself may read as a certificate problem (which preflight reports as
  # withdrawn). A failure of the machinery around it is a failure of the job.
  kc_pass="$(openssl rand -hex 24)" || die "could not make a keychain password."
  [ -n "${kc_pass}" ] || die "could not make a keychain password."
  p12="${PRIVATE_DIR}/cert.p12"
  if ! printf '%s' "${MAC_CERT_P12}" | base64 -D >"${p12}" 2>/dev/null; then
    CERT_PROBLEM="the certificate secret is not valid base64"
    return 1
  fi
  security create-keychain -p "${kc_pass}" "${KEYCHAIN}" || die "could not create the throwaway keychain."
  security set-keychain-settings -lut 21600 "${KEYCHAIN}" || die "could not set up the throwaway keychain."
  security unlock-keychain -p "${kc_pass}" "${KEYCHAIN}" || die "could not unlock the throwaway keychain."
  if ! security import "${p12}" -k "${KEYCHAIN}" -P "${MAC_CERT_PASSWORD}" \
    -T /usr/bin/codesign -T /usr/bin/security >/dev/null 2>&1; then
    CERT_PROBLEM="the certificate would not import (wrong password or damaged file)"
    rm -f "${p12}"
    return 1
  fi
  rm -f "${p12}"
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "${kc_pass}" "${KEYCHAIN}" >/dev/null 2>&1 ||
    die "could not allow codesign to use the imported key."
  # Put the throwaway keychain first in the search list so codesign finds the identity.
  local existing
  existing="$(security list-keychains -d user | sed 's/"//g')" || die "could not read the keychain search list."
  # shellcheck disable=SC2086 - the list is paths without spaces on a runner
  security list-keychains -d user -s "${KEYCHAIN}" ${existing} || die "could not add the throwaway keychain to the search list."

  local valid any
  valid="$(security find-identity -v -p codesigning "${KEYCHAIN}")" || die "could not list the identities in the throwaway keychain."
  valid="$(printf '%s\n' "${valid}" | awk -v t="(${TEAM_ID})" '/Developer ID Application:/ && index($0, t) { print $2 }')"
  any="$(security find-identity -p codesigning "${KEYCHAIN}")" || die "could not list the identities in the throwaway keychain."
  any="$(printf '%s\n' "${any}" | awk -v t="(${TEAM_ID})" '/Developer ID Application:/ && index($0, t) { print $2 }')"
  if [ -z "${valid}" ] && [ -n "${any}" ]; then
    CERT_PROBLEM="the Developer ID Application certificate for the pinned team is expired or its chain is not trusted"
    return 1
  fi
  if [ -z "${valid}" ]; then
    CERT_PROBLEM="the certificate file holds no Developer ID Application identity for the pinned team"
    return 1
  fi
  if [ "$(printf '%s\n' "${valid}" | grep -c .)" -ne 1 ]; then
    CERT_PROBLEM="the certificate file holds more than one Developer ID Application identity for the pinned team"
    return 1
  fi
  IDENTITY="${valid}"
  return 0
}

# Write the App Store Connect API key to a private file. Accepts the .p8 text as is, or
# base64 of it (a secret field is happier with one line).
write_notary_key() {
  NOTARY_KEY_FILE="${PRIVATE_DIR}/AuthKey.p8"
  case "${NOTARY_KEY}" in
    "-----BEGIN"*) printf '%s\n' "${NOTARY_KEY}" >"${NOTARY_KEY_FILE}" ;;
    *) printf '%s' "${NOTARY_KEY}" | base64 -D >"${NOTARY_KEY_FILE}" 2>/dev/null || return 1 ;;
  esac
  return 0
}

notary() {
  xcrun notarytool "$@" --key "${NOTARY_KEY_FILE}" --key-id "${NOTARY_KEY_ID}" --issuer "${NOTARY_ISSUER}"
}
