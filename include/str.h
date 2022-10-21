#ifndef STRING_H
#define STRING_H

#include <stdbool.h>
#include <stdlib.h>

#include "common.h"

typedef struct {
    u8 *str;
    size_t len;
} String;

bool string_cmp(String s, String t);
String string_dup(String s);
char *string_term(String s);


typedef struct String_Node {
    struct String_Node *next;
    String string;
} String_Node;

typedef struct {
    String_Node *head;
    String_Node *tail;
    size_t total_len;
    size_t list_size;
} String_List;

void push_string_node(String_List *ls, String_Node *n);
void push_string(String_List *ls, String s);

String_List string_split(String s, u8 delim);
String string_list_concat(String_List ls);
String string_list_join(String_List ls, u8 sep);

#endif
