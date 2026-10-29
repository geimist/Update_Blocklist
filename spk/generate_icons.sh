#!/bin/sh
# Rendert images/AutoBan.svg in die DSM-Größen.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
src="$root/images/AutoBan.svg"
ui="$root/spk/APP/ui/images"
pkg="$root/spk/PKG_DSM7"
mkdir -p "$ui"

render() {
    size=$1
    dest=$2
    if command -v rsvg-convert >/dev/null 2>&1; then
        rsvg-convert -w "$size" -h "$size" "$src" -o "$dest"
    else
        magick -background none "$src" -resize "${size}x${size}" "$dest"
    fi
}

for size in 16 24 32 48 64 256; do
    render "$size" "$ui/icon_${size}.png"
done
cp "$ui/icon_64.png" "$pkg/PACKAGE_ICON.PNG"
cp "$ui/icon_256.png" "$pkg/PACKAGE_ICON_256.PNG"
echo "icons: $ui and $pkg"
