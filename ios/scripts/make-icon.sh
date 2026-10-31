#!/usr/bin/env bash
# Renders the app icon (1024x1024, opaque, as App Store Connect requires) from
# AppHost/AppIcon.svg. Needs rsvg-convert and ImageMagick.
set -euo pipefail
cd "$(dirname "$0")/.."
out=AppHost/Assets.xcassets/AppIcon.appiconset/AppIcon.png
tmp=$(mktemp --suffix=.png)
rsvg-convert -w 1024 -h 1024 AppHost/AppIcon.svg -o "$tmp"
magick "$tmp" -background '#1E2A8F' -alpha remove -alpha off -strip "PNG24:$out"
rm -f "$tmp"
echo "wrote $out"
