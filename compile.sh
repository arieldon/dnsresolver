#!/usr/bin/env sh

set -eux

DEBUG="-DDEBUG -g -O1"
WARNINGS="-Wall -Wextra"

MEMORY="-fsanitize=alignment,bounds,array-bounds,local-bounds,memory,pointer-overflow,undefined -fsanitize-memory-track-origins"
ADDRESS="-fsanitize=address,undefined"
SANITIZER="-fno-omit-frame-pointer"

clang $WARNINGS $DEBUG $ADDRESS $SANITIZER -Iinclude/ src/* -o dnsresolver
