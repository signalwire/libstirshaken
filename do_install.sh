#!/usr/bin/env bash
set -euo pipefail

readonly REPO_URL="https://freeswitch.signalwire.com/repo/deb/debian-release"
readonly KEYRING_PATH="/usr/share/keyrings/signalwire-freeswitch-repo.gpg"
readonly SOURCE_PATH="/etc/apt/sources.list.d/freeswitch-stir-deps.list"
readonly AUTH_PATH="/etc/apt/auth.conf.d/signalwire-freeswitch.conf"

log() {
  printf '%s\n' "$*"
}

install_base_tools() {
  log "Installing base apt tools"
  sudo apt-get update
  sudo apt-get install --yes ca-certificates curl lsb-release
}

install_repository_keyring() {
  log "Installing SignalWire repository keyring"
  sudo install -d -m 0755 "$(dirname "${KEYRING_PATH}")"
  if [ -n "${SIGNALWIRE_TOKEN:-}" ]; then
    sudo curl --fail --silent --show-error --location --user "signalwire:${SIGNALWIRE_TOKEN}" "${REPO_URL}/signalwire-freeswitch-repo.gpg" --output "${KEYRING_PATH}"
  else
    sudo curl --fail --silent --show-error --location "${REPO_URL}/signalwire-freeswitch-repo.gpg" --output "${KEYRING_PATH}"
  fi
  sudo chmod 0644 "${KEYRING_PATH}"
}

configure_repository_auth() {
  if [ -z "${SIGNALWIRE_TOKEN:-}" ]; then
    return 0
  fi
  log "Configuring apt repository auth"
  sudo install -d -m 0755 "$(dirname "${AUTH_PATH}")"
  printf 'machine freeswitch.signalwire.com login signalwire password %s\n' "${SIGNALWIRE_TOKEN}" | sudo tee "${AUTH_PATH}" >/dev/null
  sudo chmod 0600 "${AUTH_PATH}"
}

configure_repository_source() {
  local distribution_codename
  distribution_codename="$(lsb_release -sc)"
  log "Configuring SignalWire repository for ${distribution_codename}"
  printf 'deb [signed-by=%s] %s/ %s main\n' "${KEYRING_PATH}" "${REPO_URL}" "${distribution_codename}" | sudo tee "${SOURCE_PATH}" >/dev/null
  printf 'deb-src [signed-by=%s] %s/ %s main\n' "${KEYRING_PATH}" "${REPO_URL}" "${distribution_codename}" | sudo tee -a "${SOURCE_PATH}" >/dev/null
}

install_build_dependencies() {
  log "Installing build dependencies"
  sudo apt-get update
  sudo apt-get install --yes autoconf automake libcurl4-openssl-dev libjwt-dev libks2 libssl-dev libtool pkgconf uuid-dev
}

build_and_install() {
  log "Building libstirshaken"
  ./bootstrap.sh
  ./configure
  make
  make check
  sudo make install
}

main() {
  install_base_tools
  install_repository_keyring
  configure_repository_auth
  configure_repository_source
  install_build_dependencies
  build_and_install
}

main "$@"
