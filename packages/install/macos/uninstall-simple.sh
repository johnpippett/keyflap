#!/bin/bash
# Removes the simple Mac install (install-simple.sh). Installed as
# ~/Library/Application Support/Keyflap/uninstall.sh. As you, no sudo. bash 3.2.
#
#   uninstall.sh            # stop it, remove the code, the LaunchAgent and the log; keep ~/.keyflap
#   uninstall.sh --purge    # also delete ~/.keyflap: the key store, its key file and every
#                           # passkey in it, the phones, agents and saved logins
#
# Without --purge a later simple install picks the same key store up again. Your agents'
# configuration (Claude Code's MCP entry and hook) is left alone; setup made backups next to it.
set -euo pipefail

purge=0
case ${1:-} in
  '') ;;
  --purge) purge=1 ;;
  *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[[ $(id -u) -ne 0 ]] || { echo "uninstall: the simple install belongs to your account: run it without sudo" >&2; exit 1; }

label=com.keyflap.simple
app="$HOME/Library/Application Support/Keyflap"
data="$HOME/.keyflap"
plist="$HOME/Library/LaunchAgents/$label.plist"
uid=$(id -u)

if launchctl print "gui/$uid/$label" >/dev/null 2>&1; then
  launchctl bootout "gui/$uid/$label" 2>/dev/null || true
  for ((i = 0; i < 80; i++)); do
    launchctl print "gui/$uid/$label" >/dev/null 2>&1 || break
    sleep 0.5
  done
fi
pkill -9 -f "$app/browsers/" 2>/dev/null || true
rm -f "$plist"
rm -rf "$HOME/Library/Logs/Keyflap"
rm -rf "$app"

if [[ $purge -eq 1 ]]; then
  rm -rf "$data"
  echo "Removed the simple install and its data ($data: key store, key file, database)."
else
  echo "Removed the simple install (code, LaunchAgent, log). Kept $data (key store, key file,"
  echo "database): a later simple install uses it again. --purge deletes it."
fi
echo "Claude Code still lists the keyflap MCP server and hook: remove them with 'claude mcp remove keyflap'"
echo "and by deleting the keyflap UserPromptSubmit hook from your Claude Code settings."
