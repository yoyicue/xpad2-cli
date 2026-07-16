#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
LOCK="$ROOT/sources.lock.json"

for command in git jq; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 1
  }
done

GH_AUTHENTICATED=0
if command -v gh >/dev/null && gh auth status --hostname github.com >/dev/null 2>&1; then
  GH_AUTHENTICATED=1
elif ! command -v curl >/dev/null; then
  printf 'source verification requires authenticated gh or curl\n' >&2
  exit 1
fi

github_api() {
  local endpoint=$1 attempt output
  for attempt in 1 2 3; do
    if [[ "$GH_AUTHENTICATED" == 1 ]]; then
      endpoint=${endpoint#https://api.github.com/}
      if output=$(gh api "$endpoint"); then
        printf '%s\n' "$output"
        return 0
      fi
    elif output=$(curl --fail --silent --show-error --location \
      -H 'Accept: application/vnd.github+json' "$endpoint"); then
      printf '%s\n' "$output"
      return 0
    fi
    sleep "$attempt"
  done
  return 1
}

jq -e '
  .schema == 1 and
  (.sources | length > 0) and
  all(.sources[];
    (.component | type == "string" and length > 0) and
    (.repository | test("^https://github\\.com/[^/]+/[^/]+$")) and
    (.tag | type == "string" and length > 0) and
    (.commit | test("^[0-9a-f]{40}$")) and
    ((.tag_commit // .commit) | test("^[0-9a-f]{40}$")) and
    (if .commit != (.tag_commit // .commit)
      then (.workflow_run | type == "number" and . > 0) and
        (.workflow_artifact | type == "string" and length > 0)
      else true
    end) and
    (.license | type == "string" and length > 0)
  )
' "$LOCK" >/dev/null || {
  printf 'invalid source lock: every component needs a canonical GitHub URL, tag, commit and license\n' >&2
  exit 1
}

verified=0
while IFS=$'\t' read -r repository tag expected tag_expected workflow_run \
  workflow_artifact; do
  slug=${repository#https://github.com/}
  canonical=$(github_api "https://api.github.com/repos/$slug" | jq -r '.html_url')
  [[ "$canonical" == "$repository" ]] || {
    printf 'non-canonical or renamed repository: locked=%s canonical=%s\n' \
      "$repository" "$canonical" >&2
    exit 1
  }

  refs=$(git ls-remote --tags "$repository" \
    "refs/tags/$tag" "refs/tags/$tag^{}")
  resolved=$(printf '%s\n' "$refs" |
    awk -v ref="refs/tags/$tag^{}" '$2 == ref { print $1; exit }')
  if [[ -z "$resolved" ]]; then
    resolved=$(printf '%s\n' "$refs" |
      awk -v ref="refs/tags/$tag" '$2 == ref { print $1; exit }')
  fi
  [[ -n "$resolved" ]] || {
    printf 'source tag not found: %s %s\n' "$repository" "$tag" >&2
    exit 1
  }
  [[ "$resolved" == "$tag_expected" ]] || {
    printf 'source identity mismatch: %s %s expected=%s actual=%s\n' \
      "$repository" "$tag" "$tag_expected" "$resolved" >&2
    exit 1
  }

  if [[ "$expected" != "$tag_expected" ]]; then
    run=$(github_api "https://api.github.com/repos/$slug/actions/runs/$workflow_run")
    jq -e --arg commit "$expected" '
      .head_sha == $commit and
      .event == "push" and
      .status == "completed" and
      .conclusion == "success"
    ' <<<"$run" >/dev/null || {
      printf 'workflow provenance mismatch: %s run=%s expected_commit=%s\n' \
        "$repository" "$workflow_run" "$expected" >&2
      exit 1
    }
    artifacts_url=$(jq -r '.artifacts_url' <<<"$run")
    artifacts=$(github_api "$artifacts_url")
    jq -e --arg artifact "$workflow_artifact" '
      any(.artifacts[]; .name == $artifact)
    ' <<<"$artifacts" >/dev/null || {
      printf 'workflow artifact missing: %s run=%s artifact=%s\n' \
        "$repository" "$workflow_run" "$workflow_artifact" >&2
      exit 1
    }
  fi

  printf 'SOURCE_OK repository=%s tag=%s tag_commit=%s build_commit=%s workflow_run=%s artifact=%s\n' \
    "$repository" "$tag" "$resolved" "$expected" "${workflow_run:-none}" \
    "${workflow_artifact:-none}"
  verified=$((verified + 1))
done < <(jq -r '.sources[] |
  [.repository, .tag, .commit, (.tag_commit // .commit),
    (.workflow_run // ""), (.workflow_artifact // "")] |
  @tsv' "$LOCK" | sort -u)

printf 'XPAD2_SOURCES_VERIFY_OK entries=%s\n' "$verified"
