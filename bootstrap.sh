#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
  printf '%s\n' "$*"
}

configure_git_hooks() {
  if git -C "${SCRIPT_DIR}" rev-parse --is-inside-work-tree >/dev/null 2>&1 && [ -d "${SCRIPT_DIR}/.githooks" ]; then
    log "Configuring git hooks path"
    git -C "${SCRIPT_DIR}" config core.hooksPath .githooks
  fi
}

bootstrap_autotools() {
  log "Regenerating autotools files"
  autoreconf -fi
}

main() {
  cd "${SCRIPT_DIR}"
  configure_git_hooks
  bootstrap_autotools
}

main "$@"
