#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arena.h"
#include "common.h"
#include "dns.h"

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

    Address addr = { .type = IPv6 };
    char *name_server = "2001:503:ba3e::2:30";

    for (;;) {
        int sockfd = socket(addr.type, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("socket()");
            exit(1);
        }

        DNS_Query query = {
            .header = {
                .id = rand(),
                .flags = 0x0100, // TODO(ariel) Create enum for flags.
                .qdcount = 1,
            },
            .question = {
                .domain = {
                    .str = (u8 *)(*argv),
                    .len = strlen(*argv),
                },
                .qclass = RR_CLASS_IN,
            },
        };

        switch (addr.type) {
            case IPv4: {
                query.question.qtype = RR_TYPE_A;
                addr.ipsize = sizeof(addr.ip);
                struct sockaddr_in *sa = (struct sockaddr_in *)addr.ip;
                sa->sin_family = AF_INET;
                sa->sin_port = DNS_PORT;
                if (inet_pton(IPv4, name_server, &sa->sin_addr) <= 0) {
                    perror("inet_pton()");
                    exit(1);
                }
                break;
            }
            case IPv6: {
                query.question.qtype = RR_TYPE_AAAA;
                addr.ipsize = sizeof(addr.ip);
                struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr.ip;
                sa->sin6_family = AF_INET6;
                sa->sin6_port = DNS_PORT;
                if (inet_pton(IPv6, name_server, &sa->sin6_addr) <= 0) {
                    perror("inet_pton()");
                    exit(1);
                }
                break;
            }
            default: assert(!"UNREACHABLE");
        }

        send_query(query, sockfd, addr);
        DNS_Reply reply = recv_reply(sockfd, addr);

        if (reply.header.ancount) {
            Resource_Record *rr = &reply.answer->rr;
            fprintf(stdout, "%.*s %.*s\n",
                    (int)rr->name.len, rr->name.str,
                    (int)rr->rdlength, rr->rdata);
            goto exit;
        } else if (reply.header.nscount) {
            bool no_match = true;
            Resource_Record_Link *link = reply.authority;

            while (link) {
                String domain = {
                    .str = link->rr.rdata,
                    .len = link->rr.rdlength,
                };

                Resource_Record *rr = find_resource_record(reply.additional, domain);
                if (rr) {
                    name_server = (char *)rr->rdata;
                    switch (rr->type) {
                        case RR_TYPE_A:
                            addr.type = IPv4;
                            break;
                        case RR_TYPE_AAAA:
                            addr.type = IPv6;
                            break;
                        default: assert(!"UNREACHABLE");
                    }
                    no_match = false;
                    break;
                }

                link = link->next;
            }

            if (no_match) {
                // NOTE(ariel) The program failed to match a name server to an
                // IP address -- failed to match NS to A record.
                fprintf(stderr, "error: unable to resolve domain name\n");
                goto exit;
            }
        } else {
            // NOTE(ariel) The program received a reply that it failed to gain
            // anything useful from, like the domain name of a TLD server or an
            // IP of some sort.
            fprintf(stderr, "error: unable to resolve domain name\n");
            goto exit;
        }

        close(sockfd);
        arena_clear(&g_arena);
    }

exit:
    arena_release(&g_arena);
    exit(0);
}
