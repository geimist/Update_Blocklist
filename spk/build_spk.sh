#!/bin/sh
# Packt AutoBan_<version>.spk
set -eu
root=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$root/.." && pwd)
version=${1:-1.0.0}
case "$version" in
    -v=*) version=${version#-v=} ;;
esac

"$root/generate_icons.sh"
if [ "${SKIP_BINARIES:-}" != 1 ]; then
    "$root/build_binaries.sh"
fi

mkdir -p "$root/APP/bin" "$root/APP/share"
# Paketskript liegt unter spk/update_blocklist.sh – nicht das Standalone-Skript im Repo-Root.
cp "$root/update_blocklist.sh" "$root/APP/bin/update_blocklist.sh"
cp "$root/internal/appdb/schema.sql" "$root/APP/share/schema.sql"
chmod 755 "$root/APP/bin/update_blocklist.sh" "$root/APP/bin/autoban-scheduler.sh" "$root/APP/ui/index.cgi"
chmod -R 755 "$root/APP/ui/texts"
chmod 755 "$root/PKG_DSM7/scripts/"* "$root/PKG_DSM7/scripts/backup/"*

# macOS-tar schreibt sonst AppleDouble (._INFO) und Pax-Header. DSM meldet das als ungültiges Dateiformat.
# Vorgehen wie in synOCR/build_spk.sh: ustar, keine xattrs, Einträge heißen INFO und nicht ./INFO.
export COPYFILE_DISABLE=1
tar_opts="--format=ustar"
if tar --help 2>&1 | grep -q -- '--no-xattrs'; then
    tar_opts="$tar_opts --no-xattrs"
fi
if tar --help 2>&1 | grep -q -- '--no-mac-metadata'; then
    tar_opts="$tar_opts --no-mac-metadata"
fi

# Version in INFO setzen, ohne die Vorlage dauerhaft zu verbiegen.
stage=$(mktemp -d "${TMPDIR:-/tmp}/autoban-spk.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
cp -R "$root/PKG_DSM7/." "$stage/"
find "$stage" "$root/APP" -name '._*' -delete
find "$stage" "$root/APP" -name '.DS_Store' -delete
if command -v xattr >/dev/null 2>&1; then
    xattr -cr "$stage" "$root/APP" 2>/dev/null || true
fi
sed -i.bak "s/^version=.*/version=\"${version}\"/" "$stage/INFO"
rm -f "$stage/INFO.bak"

# fakeroot ist auf manchen macOS-Hosts ohne SYSV-IPC unbrauchbar; DSM setzt
# die Eigentümer beim Installieren über privilege ohnehin.
run_tar() {
    if command -v fakeroot >/dev/null 2>&1 && fakeroot true >/dev/null 2>&1; then
        fakeroot tar "$@"
    else
        tar "$@"
    fi
}
# shellcheck disable=SC2086
run_tar $tar_opts --exclude='.DS_Store' --exclude='._*' \
    -C "$root/APP" -czf "$stage/package.tgz" .
out="$repo/AutoBan_${version}.spk"
(
    cd "$stage"
    # shellcheck disable=SC2086
    run_tar $tar_opts --exclude='.DS_Store' --exclude='._*' \
        -cf "$out" INFO PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG package.tgz conf scripts
)
echo "wrote $out"
