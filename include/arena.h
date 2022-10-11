#ifndef ARENA_H
#define ARENA_H

#include <stdlib.h>

#include "common.h"

typedef struct {
    void *buf;
    size_t cap;
    size_t prev;
    size_t curr;
} Arena;

extern Arena g_arena;

void arena_init(Arena *arena);
void arena_release(Arena *arena);

void *arena_alloc(Arena *arena, size_t size);
void *arena_realloc(Arena *arena, size_t size);
void arena_clear(Arena *arena);


typedef struct {
    Arena *arena;
    size_t prev;
    size_t curr;
} Arena_Checkpoint;

Arena_Checkpoint arena_checkpoint_set(Arena *arena);
void arena_checkpoint_restore(Arena_Checkpoint checkpoint);

#endif
