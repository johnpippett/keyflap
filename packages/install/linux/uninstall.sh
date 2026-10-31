#!/usr/bin/env bash
# Removes the Keyflap broker's service-mode install (packages/install/linux/install.sh).
#
#   sudo packages/install/linux/uninstall.sh            # keep data, users and credentials
#   sudo packages/install/linux/uninstall.sh --purge    # also delete them: the key store,
#                                                       # its KEK and every passkey in it
#
# Without --purge a later install.sh picks the same key store up again.
set -euo pipefail

purge=0
case ${1:-} in
  '') ;;
  --purge) purge=1 ;;
  *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[[ $EUID -eq 0 ]] || { echo "uninstall: run as root (sudo)" >&2; exit 1; }

units=(keyflap-approver.service keyflap-core.service keyflap-signer.service keyflap-approver.socket
  keyflap-core-approver.socket keyflap-core-intent.socket keyflap-core-admin.socket keyflap-signer.socket
  keyflap-signer-admin.socket)
systemctl disable --now "${units[@]}" 2>/dev/null || true
for u in "${units[@]}"; do rm -f "/etc/systemd/system/$u"; done
rm -rf /etc/systemd/system/keyflap-core.service.d /etc/systemd/system/keyflap-approver.service.d \
  /etc/systemd/system/keyflap-signer.service.d
rm -f /etc/tmpfiles.d/keyflap.conf /usr/local/bin/keyflap
systemctl daemon-reload
rm -rf /run/keyflap /run/keyflap-signer /run/keyflap-approver /var/log/keyflap
# Password tools you installed into /opt/keyflap/tools stay unless --purge.
rm -rf /opt/keyflap/app /opt/keyflap/node /opt/keyflap/browsers /opt/keyflap/bin /opt/keyflap/.stage.*
rmdir /opt/keyflap 2>/dev/null || true
rm -f /etc/keyflap/core.json /etc/keyflap/signer.json /etc/keyflap/approver.json

if [[ $purge -eq 1 ]]; then
  rm -rf /var/lib/keyflap /etc/keyflap /etc/sysusers.d/keyflap.conf /opt/keyflap
  for u in keyflap-core keyflap-signer keyflap-web; do
    if id -u "$u" >/dev/null 2>&1; then userdel "$u"; fi
    if getent group "$u" >/dev/null; then groupdel "$u" 2>/dev/null || true; fi
  done
  echo "Removed the broker, its data (key store, broker database), credentials and users."
else
  echo "Removed the broker's code and units. Kept: /var/lib/keyflap (key store, database),"
  echo "/etc/keyflap/credentials (KEK) and the keyflap-core/keyflap-signer/keyflap-web users. --purge deletes them."
fi
