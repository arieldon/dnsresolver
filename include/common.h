#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>

#define internal static
#define global static

typedef uint8_t  u8;
typedef int8_t   i8;
typedef uint16_t u16;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef uint64_t u64;
typedef int64_t  i64;

#define MIN(a, b) (a < b ? a : b)
#define MAX(a, b) (a > b ? a : b)

#define KB(n) (n << 10)
#define MB(n) (n << 20)
#define GB(n) (((u64)n) << 30)
#define TB(n) (((u64)n) << 40)

#ifdef DEBUG
#   if __GNUC__
#       define assert(c) if (!(c)) __builtin_trap()
#   elif _MSC_VER
#       define assert(c) if (!(c)) __debugbreak()
#   else
#       define assert(c) if (!(c)) *(volatile int *)0 = 0
#   endif
#else
#   include <assert.h>
#endif

#ifdef DEBUG
#    define breakpoint() asm("int $3")
#endif

#endif
