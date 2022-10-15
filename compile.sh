#!/usr/bin/env sh

set -eux

DEBUG="-DDEBUG -g -O0"
WARNINGS="-Wall -Wextra -Wpedantic"

MEMORY="-fsanitize=alignment,bounds,array-bounds,local-bounds,memory,pointer-overflow,undefined -fsanitize-memory-track-origins -fno-omit-frame-pointer"
ADDRESS="-fsanitize=address,alignment,bounds,array-bounds,local-bounds,pointer-overflow,undefined -fno-omit-frame-pointer"

gcc -D_FORTIFY_SOURCE=2 $WARNINGS -Iinclude/ src/* -o dnsresolver
