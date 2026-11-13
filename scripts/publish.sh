#!/usr/bin/env bash
# Hand the signed DMGs back: a draft release in the source repository, never published.
#
# Inputs (environment):
#   HALLMARK_SIGNED       directory holding one DMG per build the policy lists, and the leg files
#   HALLMARK_SOURCE_REPO  from the verify job's validated output
#   HALLMARK_SOURCE_SHA, HALLMARK_REQUEST_ID  likewise
#   HALLMARK_POLICY       the policy secret; the Team ID and the DMG names are read from it
#   GH_TOKEN              HALLMARK_RELEASE_TOKEN (Contents write, Actions read, that repo only)
#
# Before anything leaves, each DMG is checked again here: signed by the pinned team, stapled.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib.sh
. "${ROOT}/scripts/lib.sh"

trap 'annotate error "publishing stopped at line ${LINENO} of publish.sh."' ERR

require_env HALLMARK_SIGNED HALLMARK_SOURCE_REPO HALLMARK_SOURCE_SHA HALLMARK_REQUEST_ID GH_TOKEN \
  GITHUB_REPOSITORY GITHUB_RUN_ID

load_facts
DMG_NAMES=()
while IFS= read -r name; do DMG_NAMES+=("${name}"); done < <(fact dmg_names)
[ "${#DMG_NAMES[@]}" -gt 0 ] || die "the policy lists no builds for this request."
forget_policy
[[ "${HALLMARK_SOURCE_REPO}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "the source repository name is malformed."
[[ "${HALLMARK_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]] || die "the source commit id is malformed."
[[ "${HALLMARK_REQUEST_ID}" =~ ^[0-9]+-[0-9]+$ ]] || die "the request id is malformed."

for name in "${DMG_NAMES[@]}"; do
  dmg="${HALLMARK_SIGNED}/${name}"
  [ -f "${dmg}" ] || die "${name} is missing from the signing results."
  codesign --verify --strict "${dmg}" || die "${name} no longer verifies."
  team="$(codesign -dv --verbose=4 "${dmg}" 2>&1 | sed -n 's/^TeamIdentifier=//p')"
  [ "${team}" = "${TEAM_ID}" ] || die "${name} is signed by a different team than the policy pins."
  xcrun stapler validate "${dmg}" || die "${name} has no notarization ticket stapled."
done

RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
python3 "${ROOT}/scripts/make_result.py" "${HALLMARK_SIGNED}" "${HALLMARK_SOURCE_SHA}" "${HALLMARK_REQUEST_ID}" "${RUN_URL}" "${DMG_NAMES[@]}" ||
  die "result.json could not be built."

TAG="mac-signing-${HALLMARK_REQUEST_ID}"

# A re-run of this job must not leave two drafts. Only a draft is ever removed.
existing="$(gh release list --repo "${HALLMARK_SOURCE_REPO}" --limit 100 --json tagName,isDraft \
  --jq "[.[] | select(.tagName == \"${TAG}\" and .isDraft)] | length")"
if [ "${existing}" != "0" ]; then
  gh release delete "${TAG}" --repo "${HALLMARK_SOURCE_REPO}" --yes
fi

gh release create "${TAG}" \
  --repo "${HALLMARK_SOURCE_REPO}" \
  --draft \
  --target "${HALLMARK_SOURCE_SHA}" \
  --title "Mac signing ${HALLMARK_REQUEST_ID}" \
  --notes "Signed Mac builds for request ${HALLMARK_REQUEST_ID}. Never published; the source workflow collects the files and deletes this draft." \
  "${DMG_NAMES[@]/#/${HALLMARK_SIGNED}/}" \
  "${HALLMARK_SIGNED}/result.json"

echo "draft release ${TAG} created in ${HALLMARK_SOURCE_REPO}"
