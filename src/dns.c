#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "arena.h"
#include "common.h"
#include "dns.h"
#include "str.h"


#define SERIALIZE_U8(i) \
    do { \
        assert(sizeof(i) == sizeof(u8)); \
        if (cur + sizeof(i) >= buf + UDP_MSG_LIMIT) abort(); \
        *cur++ = i; \
    } while (0);
#define SERIALIZE_U16(i) \
    do { \
        assert(sizeof(i) == sizeof(u16)); \
        if (cur + sizeof(i) >= buf + UDP_MSG_LIMIT) abort(); \
        *cur++ = i >> 8; *cur++ = i; \
    } while (0);
#define SERIALIZE_STR(s) \
    do { \
        if (cur + s.len >= buf + UDP_MSG_LIMIT) abort(); \
        memcpy(cur, s.str, s.len); \
        cur += label.len; \
    } while (0);
#define SERIALIZE_HEADER_FIELD(i) \
    do { \
        assert(cur + sizeof(i) <= header + DNS_HEADER_LIMIT); \
        SERIALIZE_U16(i); \
    } while (0);

#define DESERIALIZE_U8(i) \
    do { \
        assert(sizeof(i) == sizeof(u8)); \
        i = *cur++; \
    } while (0);
#define DESERIALIZE_U16(i) \
    do { \
        assert(sizeof(i) == sizeof(u16)); \
        memcpy(&i, cur, sizeof(i)); \
        i = ntohs(i); \
        cur += sizeof(u16); \
    } while (0);
#define DESERIALIZE_I32(i) \
    do { \
        assert(sizeof(i) == sizeof(i32)); \
        memcpy(&i, cur, sizeof(i)); \
        i = ntohl(i); \
        cur += sizeof(i32); \
    } while(0);
#define DESERIALIZE_DOMAIN(s) \
    do { \
        cur += parse_domain(&s, buf, cur); \
    } while (0);


typedef enum { RR_CLASS_IN = 1 } RR_Class;

typedef enum {
    RR_TYPE_A     = 1,
    RR_TYPE_NS    = 2,
    RR_TYPE_AAAA  = 28,
} RR_Type;


internal size_t
format_query(DNS_Query query, u8 *buf)
{
    u8 *cur = buf;


    /* ---
     * Serialize the header of the DNS query.
     * ---
     */
    {
        u8 *header = cur;

        SERIALIZE_HEADER_FIELD(query.header.id);
        SERIALIZE_HEADER_FIELD(query.header.flags);
        SERIALIZE_HEADER_FIELD(query.header.qdcount);
        SERIALIZE_HEADER_FIELD(query.header.ancount);
        SERIALIZE_HEADER_FIELD(query.header.nscount);
        SERIALIZE_HEADER_FIELD(query.header.arcount);

        // NOTE(ariel) Confirm the entire header has been written.
        assert(cur == header + DNS_HEADER_LIMIT);
    }


    /* ---
     * Serialize question section of DNS query.
     * ---
     */
    {
        Arena_Checkpoint cp = arena_checkpoint_set(&g_arena);

        String_List ls = string_split(query.question.domain, '.');
        String_Node *n = ls.head;

        while (n) {
            String label = n->string;
            if (label.len) {
                SERIALIZE_U8((u8)label.len);
                SERIALIZE_STR(label);
            }
            n = n->next;
        }

        // NOTE(ariel) Terminate QNAME with the zero length octet (byte) for
        // the null label of the root.
        SERIALIZE_U8((u8)0);

        SERIALIZE_U16(query.question.qtype);
        SERIALIZE_U16(query.question.qclass);

        arena_checkpoint_restore(cp);
    }


    return cur - buf;
}

void
send_query(DNS_Query query, int sockfd, struct sockaddr_in sa)
{
    u8 buf[UDP_MSG_LIMIT] = {0};

    size_t len = format_query(query, (u8 *)buf);
    if (sendto(sockfd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        perror("sendto()");
        exit(1);
    }
}

internal String
parse_ipv4_addr(u8 *cur)
{
    String addr = { .len = INET_ADDRSTRLEN };
    addr.str = arena_alloc(&g_arena, addr.len);

    i32 len = snprintf((char *)addr.str, addr.len, "%d.%d.%d.%d", cur[0], cur[1], cur[2], cur[3]);
    if (len == -1) {
        perror("snprintf()");
        exit(1);
    }
    assert((u32)len <= addr.len);
    addr.str = arena_realloc(&g_arena, len);
    addr.len = len;

    return addr;
}

internal String
parse_ipv6_addr(u8 *cur)
{
    String addr = { .len = INET6_ADDRSTRLEN };
    addr.str = arena_alloc(&g_arena, addr.len);

    i32 len = snprintf((char *)addr.str, addr.len, "%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
            cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7],
            cur[8], cur[9], cur[10], cur[11], cur[12], cur[13], cur[14], cur[15]);
    if (len == -1) {
        perror("snprintf()");
        exit(1);
    }
    assert((u32)len <= addr.len);
    addr.str = arena_realloc(&g_arena, len);
    addr.len = len;

    return addr;
}

internal size_t
parse_domain(String *domain, String buf, u8 *cur)
{
    u8 *checkpoint = cur;

    u8 pointer_mask = 0xc0;
    String_List labels = {0};

    for (;;) {
        u8 len = 0;
        DESERIALIZE_U8(len);
        if (!len) {
            break;
        } else if ((pointer_mask & len) == pointer_mask) {
            --cur;

            u16 offset = 0;
            DESERIALIZE_U16(offset);
            offset &= ~(pointer_mask << 8);

            // NOTE(ariel) Ensure cursor remains within bounds.
            if (cur < buf.str || cur > buf.str + buf.len) abort();

            (void)parse_domain(domain, buf, buf.str + offset);
            push_string(&labels, *domain);

            break;
        } else {
            String_Node *label = arena_alloc(&g_arena, sizeof(String_Node));
            label->string.str = cur;
            label->string.len = len;
            push_string_node(&labels, label);
            cur += len;
        }
    }

    *domain = string_list_join(labels, '.');
    return cur - checkpoint;
}

internal size_t
parse_resource_record(Resource_Record_Link **rrs, String buf, u8 *cur)
{
    u8 *checkpoint = cur;

    Resource_Record_Link *link = arena_alloc(&g_arena, sizeof(Resource_Record));
    Resource_Record *rr = &link->rr;

    DESERIALIZE_DOMAIN(rr->name);
    DESERIALIZE_U16(rr->type);
    DESERIALIZE_U16(rr->class); assert(rr->class == RR_CLASS_IN);
    DESERIALIZE_I32(rr->ttl);
    DESERIALIZE_U16(rr->rdlength);


    /* ---
     * Parse rdata field.
     *
     * TODO(ariel) Parse CNAME resource records.
     * ---
     */
    switch (rr->type) {
        case RR_TYPE_A: {
            assert(rr->rdlength == 4);
            String addr = parse_ipv4_addr(cur);
            rr->rdlength = addr.len;
            rr->rdata = addr.str;
            cur += 4;
            break;
        }
        case RR_TYPE_NS: {
            String name = {0};
            cur += parse_domain(&name, buf, cur);
            rr->rdlength = name.len;
            rr->rdata = name.str;
            break;
        }
        case RR_TYPE_AAAA: {
            assert(rr->rdlength == 16);
            String addr = parse_ipv6_addr(cur);
            rr->rdlength = addr.len;
            rr->rdata = addr.str;
            cur += 16;
            break;
        }
        default: {
            fprintf(stderr, "error: encountered unsupported resource record type (%d)\n", rr->type);
            cur += rr->rdlength;
        }
    }


    link->next = *rrs;
    *rrs = link;

    return cur - checkpoint;
}

internal DNS_Reply
parse_reply(String buf)
{
    u8 *cur = buf.str;
    DNS_Reply reply = {0};


    /* ---
     * Parse header of DNS reply.
     * ---
     */
    {
        u8 *header = cur;

        DESERIALIZE_U16(reply.header.id);
        DESERIALIZE_U16(reply.header.flags);
        DESERIALIZE_U16(reply.header.qdcount);
        DESERIALIZE_U16(reply.header.ancount);
        DESERIALIZE_U16(reply.header.nscount);
        DESERIALIZE_U16(reply.header.arcount);

        // NOTE(ariel) Confirm the entire header has been read.
        assert(cur == header + DNS_HEADER_LIMIT);
    }


    /* ---
     * Parse question section of DNS reply.
     * ---
     */
    {
        assert(reply.header.qdcount == 1);

        cur += parse_domain(&reply.question.domain, buf, cur);
        DESERIALIZE_U16(reply.question.qtype);
        DESERIALIZE_U16(reply.question.qclass);
    }


    /* --
     * Parse answer section of DNS reply.
     * ---
     */
    for (size_t i = 0; i < reply.header.ancount; ++i)
        cur += parse_resource_record(&reply.answer, buf, cur);


    /* ---
     * Parse authority section of DNS reply.
     * ---
     */
    for (size_t i = 0; i < reply.header.nscount; ++i)
        cur += parse_resource_record(&reply.authority, buf, cur);


    /* ---
     * Parse additional records included in DNS reply.
     * ---
     */
    for (size_t i = 0; i < reply.header.arcount; ++i)
        cur += parse_resource_record(&reply.additional, buf, cur);


    return reply;
}

DNS_Reply
recv_reply(int sockfd, struct sockaddr_in sa)
{
    socklen_t socklen = sizeof(sa);
    ssize_t len = recvfrom(sockfd, NULL, 0, MSG_TRUNC | MSG_PEEK, (struct sockaddr *)&sa, &socklen);
    if (len == -1) {
        perror("recvfrom");
        exit(1);
    }

    String buf = {
        .str = arena_alloc(&g_arena, len),
        .len = len,
    };
    if (recvfrom(sockfd, buf.str, buf.len, 0, (struct sockaddr *)&sa, &socklen) == -1) {
        perror("recvfrom()");
        exit(1);
    }

    return parse_reply(buf);
}

Resource_Record *
find_resource_record(Resource_Record_Link *rrs, String name)
{
    Resource_Record_Link *link = rrs;

    while (link) {
        Resource_Record *rr = &link->rr;

        // TODO(ariel) Support IPv6 addresses. As far as I'm aware, they're
        // parsed properly, but the struct above `in_addr` doesn't support
        // IPv6. The API defines a separate type for IPv6 addresses.
        if (rr->type == RR_TYPE_AAAA) goto next;

        if (string_cmp(rr->name, name)) return rr;
next:   link = link->next;
    }

    return 0;
}
