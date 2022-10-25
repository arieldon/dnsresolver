#!/usr/bin/env sh

set -eux

DEBUG="-DDEBUG -g -O0"
RELEASE="-O2"
WARNINGS="-Wall -Wextra -Wpedantic"
FLAGS="-D_FORTIFY_SOURCE=2 $WARNINGS"

if [ $# -eq 1 ] && [ "$1" = "--debug" ]; then
    FLAGS="$FLAGS $DEBUG"
else
    FLAGS="$FLAGS $RELEASE"
fi

gcc "$FLAGS" -Iinclude/ src/* -o dnsresolver
