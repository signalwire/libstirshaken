#!/usr/bin/env bash
set -euo pipefail

readonly VERSION_FILE="VERSION"
readonly CHANGELOG_FILE="debian/changelog"
readonly PACKAGE_NAME="libstirshaken"
readonly MAINTAINER="FreeSWITCH Solutions <packages@freeswitch.com>"
readonly SEMVER_PATTERN='^[0-9]+[.][0-9]+[.][0-9]+$'
readonly USAGE="Usage: ./prepare-release.sh X.Y.Z"

log() {
  printf '%s\n' "$*"
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  printf '%s\n' "${script_dir}"
}

enter_repo_root() {
  cd "$(repo_root)"
}

require_version_argument() {
  if [ "$#" -ne 1 ]; then
    fail "${USAGE}"
  fi
  if [[ ! "$1" =~ ${SEMVER_PATTERN} ]]; then
    fail "version must use plain semver without a leading v: X.Y.Z"
  fi
}

require_clean_worktree() {
  if [ -n "$(git status --porcelain)" ]; then
    fail "working tree must be clean before preparing a release"
  fi
}

require_tag_available() {
  local tag
  tag="$1"
  if git rev-parse --verify --quiet "refs/tags/${tag}" >/dev/null; then
    fail "tag already exists: ${tag}"
  fi
}

write_version() {
  local version
  version="$1"
  printf '%s\n' "${version}" > "${VERSION_FILE}"
}

prepend_changelog_entry() {
  local version
  local date
  local current_changelog
  version="$1"
  date="$(date -R)"
  current_changelog="$(cat "${CHANGELOG_FILE}")"
  {
    printf '%s (%s-1) unstable; urgency=medium\n\n' "${PACKAGE_NAME}" "${version}"
    printf '  * Release %s.\n\n' "${version}"
    printf ' -- %s  %s\n\n' "${MAINTAINER}" "${date}"
    printf '%s\n' "${current_changelog}"
  } > "${CHANGELOG_FILE}"
}

changelog_version() {
  sed -n '1s/^.*(\([^)]*\)).*$/\1/p' "${CHANGELOG_FILE}"
}

require_consistent_versions() {
  local version
  local package_version
  local changelog_package_version
  version="$1"
  package_version="$(build/version.sh)"
  changelog_package_version="$(changelog_version)"
  if [ "${package_version}" != "${version}" ]; then
    fail "build/version.sh returned ${package_version}, expected ${version}"
  fi
  if [ "${changelog_package_version}" != "${version}-1" ]; then
    fail "${CHANGELOG_FILE} starts with ${changelog_package_version}, expected ${version}-1"
  fi
}

require_expected_changes() {
  local changes
  changes="$(git status --porcelain)"
  if [ "${changes}" != " M ${CHANGELOG_FILE}"$'\n'" M ${VERSION_FILE}" ] &&
     [ "${changes}" != " M ${VERSION_FILE}"$'\n'" M ${CHANGELOG_FILE}" ]; then
    printf '%s\n' "${changes}" >&2
    fail "release preparation changed unexpected files"
  fi
}

commit_release() {
  local version
  version="$1"
  git add "${VERSION_FILE}" "${CHANGELOG_FILE}"
  git commit -m "Release ${version}"
}

tag_release() {
  local version
  local tag
  version="$1"
  tag="v${version}"
  git tag -a "${tag}" -m "Release ${version}"
}

main() {
  local version
  require_version_argument "$@"
  version="$1"
  enter_repo_root
  require_clean_worktree
  require_tag_available "v${version}"
  log "Preparing release ${version}"
  write_version "${version}"
  prepend_changelog_entry "${version}"
  require_consistent_versions "${version}"
  require_expected_changes
  commit_release "${version}"
  tag_release "${version}"
  log "Created release commit and tag v${version}"
  log "Push with: git push origin master && git push origin v${version}"
}

main "$@"
