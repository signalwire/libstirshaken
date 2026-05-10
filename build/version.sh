#!/usr/bin/env bash
set -euo pipefail

readonly VERSION_FILE="VERSION"
readonly SEMVER_PATTERN='^[0-9]+[.][0-9]+[.][0-9]+$'

repo_root() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "${script_dir}/.." && pwd
}

version() {
  local root
  local version
  root="$(repo_root)"
  version="$(<"${root}/${VERSION_FILE}")"
  if [[ ! "${version}" =~ ${SEMVER_PATTERN} ]]; then
    printf 'Invalid %s value: %s\n' "${VERSION_FILE}" "${version}" >&2
    return 1
  fi
  printf '%s\n' "${version}"
}

main() {
  version
}

main "$@"
