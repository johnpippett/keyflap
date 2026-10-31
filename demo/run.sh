#!/bin/sh
# Builds and runs the Keyflap demo container (podman, or docker if podman isn't installed).
#
#   demo/run.sh              build (cached after the first time) and run
#   demo/run.sh --no-build   run the image you already built
#   ENGINE=docker demo/run.sh
#
# Runs in the foreground with a terminal: the approval prompts appear here and you answer
# them here. Ctrl-C stops it; nothing is kept.
set -eu

repo=$(cd "$(dirname "$0")/.." && pwd)
engine=${ENGINE:-}
if [ -z "$engine" ]; then
  if command -v podman >/dev/null 2>&1; then engine=podman
  elif command -v docker >/dev/null 2>&1; then engine=docker
  else echo "run.sh: needs podman or docker" >&2; exit 1
  fi
fi
image=${IMAGE:-localhost/keyflap-demo:latest}

if [ "${1:-}" != "--no-build" ]; then
  echo "Building $image with $engine (the first build downloads the ~2 GB Playwright image)..." >&2
  if [ "$engine" = podman ]; then
    podman build -f "$repo/demo/Containerfile" \
      --ignorefile "$repo/demo/Containerfile.dockerignore" -t "$image" "$repo"
  else
    # docker (BuildKit) picks up demo/Containerfile.dockerignore next to the Containerfile.
    docker build -f "$repo/demo/Containerfile" -t "$image" "$repo"
  fi
fi

if [ ! -t 0 ]; then
  echo "run.sh: run this in a terminal: approvals are typed into it" >&2
  exit 1
fi

# The MCP endpoint is published on the host's loopback only, and on port 8765 on both sides:
# the broker accepts only Host: 127.0.0.1:8765 / localhost:8765. No volumes: nothing persists.
exec "$engine" run --rm -it --init --name keyflap-demo \
  -p 127.0.0.1:8765:8765 \
  "$image"
