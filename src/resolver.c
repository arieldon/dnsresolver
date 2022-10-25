#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "common.h"
#include "dns.h"
#include "err_exit.h"

internal inline void
usage(char *program)
{
    fprintf(stderr, "usage: %s hostname\n", program);
    exit(1);
}

int
main(int argc, char *argv[])
{
    char *program = *argv++;
    if (argc != 2) usage(program);

    arena_init(&g_arena);

    String domain = {
        .str = (u8 *)*argv,
        .len = strlen(*argv),
    };
    output_address(resolve(domain));

    arena_release(&g_arena);
    exit(0);
}
