#!/bin/sh
# DSM ruft diese Datei über den Symlink webman/3rdparty/AutoBan auf.
# Der zeigt auf target/ui, deshalb nicht relativ zu $0 nach der Binary suchen.
set -eu
target=/var/packages/AutoBan/target
case "$(uname -m)" in
    x86_64) bin=ab-api-x86_64 ;;
    i686|i386) bin=ab-api-i686 ;;
    aarch64|arm64) bin=ab-api-aarch64 ;;
    armv7*|armv6l) bin=ab-api-armv7 ;;
    *) bin=ab-api-x86_64 ;;
esac
exec "$target/bin/ui-bin/$bin"
