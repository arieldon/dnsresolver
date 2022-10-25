#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "arena.h"
#include "common.h"
#include "dns.h"
#include "err_exit.h"
#include "str.h"


#define SERIALIZE_U8(i) \
    do { \
        assert(sizeof(i) == sizeof(u8)); \
        *cur++ = i; \
    } while (0);
#define SERIALIZE_U16(i) \
    do { \
        assert(sizeof(i) == sizeof(u16)); \
        *cur++ = i >> 8; *cur++ = i; \
    } while (0);
#define SERIALIZE_STR(s) \
    do { \
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


char *const ROOT_SERVER_A_IPv4 = "198.41.0.4";
char *const ROOT_SERVER_A_IPv6 = "2001:503:ba3e::2:30";
char *const ROOT_SERVER_E_IPv4 = "192.203.230.10";
char *const ROOT_SERVER_E_IPv6 = "2001:500:a8::e";

char *RR_TYPE_STRING[] = {
    [RR_TYPE_A]     = "A",
    [RR_TYPE_NS]    = "NS",
    [RR_TYPE_CNAME] = "CNAME",
    [RR_TYPE_AAAA]  = "AAAA",
};


internal inline void
check_addr_valid(int res)
{
    if (res == 0)
        err_exit("attempted to convert invalid address from string to network address structure");
    else if (res < 0)
        err_exit("attempted to convert an invalid address family to network address structure");
}

internal void
transform_ipv4_addr(char *ip, sockaddr_in *addr)
{
    int res = inet_pton(AF_INET, ip, &addr->sin_addr);
    check_addr_valid(res);
}

internal void
transform_ipv6_addr(char *ip, sockaddr_in6 *addr)
{
    int res = inet_pton(AF_INET6, ip, &addr->sin6_addr);
    check_addr_valid(res);
}

internal void
encode_ip(char *ip, sockaddr_storage *addr)
{
    switch (addr->ss_family) {
        case AF_INET: {
            sockaddr_in *sa = (sockaddr_in *)addr;
            sa->sin_family = AF_INET;
            sa->sin_port = DNS_PORT;
            transform_ipv4_addr(ip, sa);
            return;
        }
        case AF_INET6: {
            sockaddr_in6 *sa = (sockaddr_in6 *)addr;
            sa->sin6_family = AF_INET6;
            sa->sin6_port = DNS_PORT;
            transform_ipv6_addr(ip, sa);
            return;
        }
        default: assert(!"UNREACHABLE");
    }
}

internal DNS_Query
init_query(String hostname, int socktype)
{
    assert(socktype == AF_INET || socktype == AF_INET6);
    return (DNS_Query){
        .header = {
            .id = rand(),
            .qdcount = 1,
        },
        .question = {
            .domain = hostname,
            .qtype = socktype == AF_INET ? RR_TYPE_A : RR_TYPE_AAAA,
            .qclass = RR_CLASS_IN,
        },
    };
}

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

internal void
send_query(DNS_Query query, int sockfd, sockaddr_storage addr)
{
    u8 buf[UDP_MSG_LIMIT] = {0};
    size_t len = format_query(query, (u8 *)buf);
    if (sendto(sockfd, buf, len, 0, (sockaddr *)&addr, sizeof(addr)) == -1)
        err_exit("failed to send DNS query");
}

internal String
parse_ipv4_addr(u8 *cur)
{
    String addr = { .len = INET_ADDRSTRLEN };
    addr.str = arena_alloc(&g_arena, addr.len);

    i32 len = snprintf((char *)addr.str, addr.len, "%d.%d.%d.%d", cur[0], cur[1], cur[2], cur[3]);
    if (len == -1) err_exit("failed to parse IPv4 address");
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

    i32 len = snprintf((char *)addr.str, addr.len,
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7],
            cur[8], cur[9], cur[10], cur[11], cur[12], cur[13], cur[14], cur[15]);
    if (len == -1) err_exit("failed to parse IPv6 address");
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
            if (cur < buf.str || cur > buf.str + buf.len)
                err_exit("DNS label contains pointer to outside the bounds of the message");

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
parse_resource_record(Resource_Record_List *rs, String buf, u8 *cur)
{
    u8 *checkpoint = cur;

    Resource_Record_Link *link = arena_alloc(&g_arena, sizeof(Resource_Record_Link));
    Resource_Record *rr = &link->rr;


    /* ---
     * Parse all fields of resource record barring rdata.
     * ---
     */
    {
        DESERIALIZE_DOMAIN(rr->name);
        DESERIALIZE_U16(rr->type);
        DESERIALIZE_U16(rr->class); assert(rr->class == RR_CLASS_IN);
        DESERIALIZE_I32(rr->ttl);
        DESERIALIZE_U16(rr->rdlength);
    }


    /* ---
     * Parse rdata field.
     * ---
     */
    switch (rr->type) {
        case RR_TYPE_A: {
            assert(rr->rdlength == 4);
            String addr = parse_ipv4_addr(cur);
            rr->rdlength = addr.len;
            rr->rdata = addr.str;
            cur += 4;

            link->next = rs->A;
            rs->A = link;
            break;
        }
        case RR_TYPE_NS: {
            String name = {0};
            cur += parse_domain(&name, buf, cur);
            rr->rdlength = name.len;
            rr->rdata = name.str;

            link->next = rs->NS;
            rs->NS = link;
            break;
        }
        case RR_TYPE_CNAME: {
            String canon = {0};
            cur += parse_domain(&canon, buf, cur);
            rr->rdlength = canon.len;
            rr->rdata = canon.str;

            link->next = rs->CNAME;
            rs->CNAME = link;
            break;
        }
        case RR_TYPE_AAAA: {
            assert(rr->rdlength == 16);

            String addr = parse_ipv6_addr(cur);
            rr->rdlength = addr.len;
            rr->rdata = addr.str;
            cur += 16;

            link->next = rs->AAAA;
            rs->AAAA = link;
            break;
        }
        default: {
            cur += rr->rdlength;
            break;
        }
    }


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

internal DNS_Reply
recv_reply(int sockfd, sockaddr_storage addr)
{
    socklen_t socklen = sizeof(addr);
    ssize_t len = recvfrom(sockfd, 0, 0, MSG_TRUNC | MSG_PEEK, (sockaddr *)&addr, &socklen);
    if (len == -1) err_exit("failed to read length of received message");

    String buf = {
        .str = arena_alloc(&g_arena, len),
        .len = len,
    };
    if (recvfrom(sockfd, buf.str, buf.len, 0, (sockaddr *)&addr, &socklen) == -1)
        err_exit("failed to read received message");

    return parse_reply(buf);
}

internal DNS_Reply
query(char *server, sockaddr_storage addr, String hostname)
{
    int sockfd = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (sockfd == -1) err_exit("failed to open socket");

    struct timeval timeout = { .tv_sec = 1 };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1)
        err_exit("failed to set timeout option for socket");

    encode_ip(server, &addr);

    send_query(init_query(hostname, addr.ss_family), sockfd, addr);
    DNS_Reply reply = recv_reply(sockfd, addr);

    close(sockfd);
    return reply;
}

internal Resource_Record *
find_resource_record(Resource_Record_List rs, String name)
{
    Resource_Record_Link *link = 0;

    link = rs.A;
    while (link) {
        Resource_Record *rr = &link->rr;
        if (string_cmp(rr->name, name)) return rr;
        link = link->next;
    }

    link = rs.AAAA;
    while (link) {
        Resource_Record *rr = &link->rr;
        if (string_cmp(rr->name, name)) return rr;
        link = link->next;
    }

    return 0;
}

Resource_Record_List
resolve(String domain)
{
    char *ip = ROOT_SERVER_A_IPv4;
    sockaddr_storage addr = { .ss_family = AF_INET };

    for (;;) {
        Arena_Checkpoint cp = arena_checkpoint_set(&g_arena);
        DNS_Reply reply = query(ip, addr, domain);

        if (reply.header.flags & DNS_HEADER_FLAG_AA) {
            return reply.answer;
        } else if (reply.header.nscount) {
            Resource_Record_Link *link = reply.authority.NS;

            while (link) {
                String rr_domain = {
                    .str = link->rr.rdata,
                    .len = link->rr.rdlength,
                };

                // NOTE(ariel) Match resource record from authority section to
                // record from additional section to map domain name to IP
                // address.
                Resource_Record *rr = find_resource_record(reply.additional, rr_domain);
                if (rr) {
                    assert(rr->type == RR_TYPE_A || rr->type == RR_TYPE_AAAA);
                    addr.ss_family = rr->type == RR_TYPE_A ? AF_INET : AF_INET6;
                    ip = (char *)rr->rdata;
                    break;
                }

                link = link->next;
            }

            // NOTE(ariel) If no match exists between NS and A, query the name
            // server using its domain or hostname.
            if (!link) {
                if (reply.authority.NS) {
                    Resource_Record *rr = &reply.authority.NS->rr;
                    String nameserver_domain = {
                        .str = rr->rdata,
                        .len = rr->rdlength,
                    };

                    // NOTE(ariel) Recursively resolve IP from hostname of some
                    // nameserver to then query it.
                    Resource_Record_List nameserver = resolve(nameserver_domain);
                    if (nameserver.A) {
                        Resource_Record *rr = &nameserver.A->rr;
                        ip = string_term((String){ .str = rr->rdata, .len = rr->rdlength });
                    } else if (nameserver.AAAA) {
                        Resource_Record *rr = &nameserver.A->rr;
                        ip = string_term((String){ .str = rr->rdata, .len = rr->rdlength });
                    } else err_exit("unable to recursively resolve domain name of nameserver");
                } else err_exit("DNS reply does not contain expected NS record");
            }
        } else err_exit("DNS reply does not contain any NS records");

        arena_checkpoint_restore(cp);
    }
}

void
output_address(Resource_Record_List rs)
{
    if (rs.A) {
        Resource_Record *rr = &rs.A->rr;
        fprintf(stdout, "(%s) %.*s %.*s\n",
                RR_TYPE_STRING[rr->type],
                (int)rr->name.len, rr->name.str,
                (int)rr->rdlength, rr->rdata);
    } else if (rs.AAAA) {
        Resource_Record *rr = &rs.AAAA->rr;
        fprintf(stdout, "(%s) %.*s %.*s\n",
                RR_TYPE_STRING[rr->type],
                (int)rr->name.len, rr->name.str,
                (int)rr->rdlength, rr->rdata);
    } else err_exit("unable to map hostname to IP address");
}
