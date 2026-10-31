#!/bin/bash
# Removes the Keyflap broker's service-mode install on macOS (packages/install/macos/install.sh).
#
#   sudo ./uninstall.sh            # keep data, users and credentials
#   sudo ./uninstall.sh --purge    # also delete them: the key store, its KEK and every passkey
#                                  # in it, and the three service users
#
# Without --purge a later install.sh picks the same key store up again. bash 3.2.
set -euo pipefail

purge=0
case ${1:-} in
  '') ;;
  --purge) purge=1 ;;
  *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[[ $(id -u) -eq 0 ]] || { echo "uninstall: run as root (sudo)" >&2; exit 1; }

labels=(com.keyflap.approver com.keyflap.core com.keyflap.signer)
users=(_keyflap-web _keyflap-core _keyflap-signer)

for label in "${labels[@]}"; do
  if launchctl print "system/$label" >/dev/null 2>&1; then
    launchctl bootout "system/$label" 2>/dev/null || true
  fi
done
# bootout returns before the job has exited; the core takes up to 30 s to save browser state.
for label in "${labels[@]}"; do
  for ((i = 0; i < 80; i++)); do
    launchctl print "system/$label" >/dev/null 2>&1 || break
    sleep 0.5
  done
done
for u in "${users[@]}"; do
  uid=$(id -u "$u" 2>/dev/null) || continue
  # Playwright's Chromium is detached from the core's process group; per-uid agents linger too.
  pkill -9 -u "$uid" 2>/dev/null || true
  launchctl bootout "user/$uid" 2>/dev/null || true
done
# drop_signer_aces PATH: removes every ACL entry for _keyflap-signer on PATH, set directly or
# inherited, and no other entry (the same function as in install.sh).
drop_signer_aces() {
  local i
  for i in $(ls -led "$1" 2>/dev/null | sed -n 's/^ *\([0-9][0-9]*\): user:_keyflap-signer .*/\1/p' | sort -rn); do
    chmod -a# "$i" "$1"
  done
}
# install.sh let the signer read Tailscale's LocalAPI token: an inheritable entry on the
# directory, and the entries each token file got from it or directly.
if [[ -d /Library/Tailscale ]]; then
  drop_signer_aces /Library/Tailscale
  for f in /Library/Tailscale/sameuserproof-*; do
    if [[ -f $f ]]; then drop_signer_aces "$f"; fi
  done
fi
for label in "${labels[@]}"; do rm -f "/Library/LaunchDaemons/$label.plist"; done
rm -f /usr/local/bin/keyflap
rm -rf /Library/Keyflap/run /Library/Keyflap/log /Library/Keyflap/etc
# Password tools you installed into /opt/keyflap/tools stay unless --purge.
rm -rf /opt/keyflap/app /opt/keyflap/node /opt/keyflap/browsers /opt/keyflap/libexec /opt/keyflap/.stage.*
rmdir /opt/keyflap 2>/dev/null || true

if [[ $purge -eq 1 ]]; then
  rm -rf /Library/Keyflap /opt/keyflap
  kept=()
  for u in "${users[@]}"; do
    if dscl . -read "/Users/$u" UniqueID >/dev/null 2>&1; then
      dscl . -delete "/Users/$u" >/dev/null 2>&1 || kept[${#kept[@]}]=$u
    fi
    if dscl . -read "/Groups/$u" PrimaryGroupID >/dev/null 2>&1; then
      dscl . -delete "/Groups/$u" >/dev/null 2>&1 || true
    fi
  done
  echo "Removed the broker, its data (key store, broker database) and credentials."
  if [[ ${#kept[@]} -gt 0 ]]; then
    cat <<EOF
Could not delete the service user(s) ${kept[*]}: macOS lets only an app with Full Disk Access
delete a user record (the error is eDSPermissionError -14120). They are hidden, have no shell
and no password, so leaving them is harmless, and a later install.sh reuses them. To delete
them: give Terminal (or, over ssh, Remote Login's "Allow full disk access for remote users")
Full Disk Access in System Settings > Privacy & Security, then run
  sudo dscl . -delete /Users/${kept[0]}
for each, and take the access away again.
EOF
  else
    echo "Removed the _keyflap-core, _keyflap-signer and _keyflap-web users."
  fi
else
  echo "Removed the broker's code and services. Kept: /Library/Keyflap/data (key store, database),"
  echo "/Library/Keyflap/credentials (KEK) and the _keyflap-core/_keyflap-signer/_keyflap-web users."
  echo "--purge deletes them."
fi
