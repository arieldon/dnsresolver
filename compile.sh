#!/usr/bin/env sh

set -eux

DEBUG="-DDEBUG -g -O0"
WARNINGS="-Wall -Wextra -Wpedantic"

gcc -D_FORTIFY_SOURCE=2 $DEBUG $WARNINGS -Iinclude/ src/* -o dnsresolver
