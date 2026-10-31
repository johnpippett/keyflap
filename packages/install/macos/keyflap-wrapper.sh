#!/bin/sh
# Keyflap broker CLI, service mode on macOS. Installed by packages/install/macos/install.sh;
# runs only the root-owned code and runtime in /opt/keyflap. Admin commands need sudo, and
# macOS sudo has no secure_path and keeps HOME, so it runs node with a clean environment:
# nothing from the caller's shell (PATH, HOME, NODE_OPTIONS, …) reaches the root process.
# Run it as: sudo keyflap …
exec /usr/bin/env -i \
  KEYFLAP_MODE=service \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  ${SUDO_UID:+SUDO_UID="$SUDO_UID"} ${SUDO_GID:+SUDO_GID="$SUDO_GID"} ${SUDO_USER:+SUDO_USER="$SUDO_USER"} \
  ${TERM:+TERM="$TERM"} ${LANG:+LANG="$LANG"} \
  /opt/keyflap/node/bin/node --disable-warning=ExperimentalWarning /opt/keyflap/app/packages/cli/src/main.ts "$@"
