#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "err_exit.h"


void
err_exit(char *fmt, ...)
{
    // NOTE(ariel) Assume this functions runs directly after previous failed
    // function. If this assumption holds, it's safe to copy `errno` and call
    // the following IO functions.
    int errcode = errno;

    va_list ap;
    va_start(ap, fmt);

    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);

    if (errcode) fprintf(stderr, "(%s)\n", strerror(errcode));
    else fprintf(stderr, "\n");

    va_end(ap);
    exit(1);
}

