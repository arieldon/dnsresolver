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
    char *hostname = *argv++;
    if (argc != 2) usage(program);

    arena_init(&g_arena);

    char *server = ROOT_SERVER_E_IPv4;
    sockaddr_storage addr = { .ss_family = AF_INET };

    for (;;) {
        int sockfd = socket(addr.ss_family, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            perror("socket()");
            exit(1);
        }

        switch (addr.ss_family) {
            case AF_INET: {
                query.question.qtype = RR_TYPE_A;
                sockaddr_in *sa = (sockaddr_in *)&addr;
                sa->sin_family = AF_INET;
                sa->sin_port = DNS_PORT;
                if (inet_pton(AF_INET, name_server, &sa->sin_addr) <= 0) {
                    perror("inet_pton()");
                    exit(1);
                }
                break;
            }
            case AF_INET6: {
                query.question.qtype = RR_TYPE_AAAA;
                sockaddr_in6 *sa = (sockaddr_in6 *)&addr;
                sa->sin6_family = AF_INET6;
                sa->sin6_port = DNS_PORT;
                if (inet_pton(AF_INET6, name_server, &sa->sin6_addr) <= 0) {
                    perror("inet_pton()");
                    exit(1);
                }
                break;
            }
            default: assert(!"UNREACHABLE");
        }

        DNS_Query query = init_query(hostname,
            addr.ss_family == AF_INET ? RR_TYPE_A : RR_TYPE_AAAA);
        send_query(query, sockfd, addr);
        DNS_Reply reply = recv_reply(sockfd, addr);

        if (reply.header.flags & DNS_HEADER_FLAG_AA) {
            if (reply.header.ancount) {
                Resource_Record *rr = &reply.answer->rr;
                fprintf(stdout, "(%s) %.*s %.*s\n",
                        RR_TYPE_STRING[rr->type],
                        (int)rr->name.len, rr->name.str,
                        (int)rr->rdlength, rr->rdata);
            } else {
                fprintf(stdout, "error: encountered authoritative reply without answer\n");
            }
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
                    server = (char *)rr->rdata;
                    switch (rr->type) {
                        case RR_TYPE_A:
                            addr.ss_family = AF_INET;
                            break;
                        case RR_TYPE_AAAA:
                            addr.ss_family = AF_INET6;
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
