#include <string.h>

#include "arena.h"
#include "str.h"

bool
string_cmp(String s, String t)
{
    if (s.len != t.len) return false;
    for (size_t i = 0; i < s.len; ++i) if (s.str[i] != t.str[i]) return false;
    return true;
}

String
string_dup(String s)
{
    String t = {0};

    t.len = s.len;
    t.str = arena_alloc(&g_arena, t.len);
    memmove(t.str, s.str, t.len);

    return t;
}

void
push_string_node(String_List *ls, String_Node *n)
{
    if (!ls->head) {
        ls->head = n;
    } else if (!ls->tail) {
        ls->head->next = n;
        ls->tail = n;
    } else {
        ls->tail->next = n;
        ls->tail = n;
    }
    ls->total_len += n->string.len;
    ++ls->list_size;
}

void
push_string(String_List *ls, String s)
{
    String_Node *n = arena_alloc(&g_arena, sizeof(String_Node));
    n->string = s;
    push_string_node(ls, n);
}

String_List
string_split(String s, u8 delim)
{
    String_List ls = {0};

    for (size_t i = 0, prev_split = 0; i < s.len; ++i) {
        if (s.str[i] == delim) {
            String_Node *n = arena_alloc(&g_arena, sizeof(String_Node));
            n->string.str = s.str + i + 1;
            n->string.len = s.len - i - 1;
            ls.total_len += n->string.len;
            ++ls.list_size;

            if (!ls.head) {
                ls.head = arena_alloc(&g_arena, sizeof(String_Node));
                ls.head->string.str = s.str;
                ls.head->string.len = i;
                ls.head->next = n;
                ls.tail = n;
                ls.total_len += i;
                ++ls.list_size;
            } else {
                ls.total_len -= ls.tail->string.len;
                ls.tail->string.len = i - prev_split - 1;
                ls.total_len += ls.tail->string.len;

                ls.tail->next = n;
                ls.tail = n;
            }

            prev_split = i;
        }
    }

#ifdef DEBUG
    size_t sum = 0;
    String_Node *n = ls.head;
    while (n) {
        sum += n->string.len;
        n = n->next;
    }
    assert(sum == ls.total_len);
#endif

    return ls;
}

String
string_list_concat(String_List ls)
{
    String s = {
        .str = arena_alloc(&g_arena, 0),
    };

    String_Node *n = ls.head;
    while (n) {
        String t = n->string;

        s.str = arena_realloc(&g_arena, s.len + t.len);
        memcpy(s.str + s.len, t.str, t.len);
        s.len += t.len;

        n = n->next;
    }

    return s;
}

String
string_list_join(String_List ls, u8 sep)
{
    if (ls.list_size == 1) {
        String t = ls.head->string;
        String s = {
            .str = arena_alloc(&g_arena, t.len),
            .len = t.len,
        };
        memcpy(s.str, t.str, t.len);
        return s;
    }

    String s = {
        .str = arena_alloc(&g_arena, 0),
    };

    String_Node *n = ls.head;
    while (n) {
        String t = n->string;

        if (n != ls.tail) {
            s.str = arena_realloc(&g_arena, s.len + t.len + 1);
            memcpy(s.str + s.len, t.str, t.len);
            s.len += t.len + 1;
            s.str[s.len - 1] = sep;
        } else {
            s.str = arena_realloc(&g_arena, s.len + t.len);
            memcpy(s.str + s.len, t.str, t.len);
            s.len += t.len;
        }

        n = n->next;
    }

    return s;
}
