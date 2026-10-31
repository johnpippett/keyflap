#!/bin/sh
# Keyflap broker CLI, service mode. Installed by packages/install/linux/install.sh; runs only
# the root-owned code and runtime in /opt/keyflap. Admin commands need sudo.
KEYFLAP_MODE=service
export KEYFLAP_MODE
exec /opt/keyflap/node/bin/node --disable-warning=ExperimentalWarning /opt/keyflap/app/packages/cli/src/main.ts "$@"
