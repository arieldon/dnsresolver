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

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket()");
        exit(1);
    }

    char *name_server = "198.41.0.4";
    for (;;) {
        DNS_Query query = {
            .header = {
                .id = rand(),
                .flags = 0x0100,
                .qdcount = 1,
            },
            .question = {
                .domain = {
                    .str = (u8 *)(*argv),
                    .len = strlen(*argv),
                },
                .qtype = 0x01,
                .qclass = 0x01,
            },
        };

        struct in_addr addr = {0};
        if (inet_aton(name_server, &addr) == 0) {
            perror("inet_aton()");
            exit(1);
        }
        struct sockaddr_in sa = {
            .sin_family = AF_INET,
            .sin_addr = addr,
            .sin_port = DNS_PORT,
        };

        arena_clear(&g_arena);
        send_query(query, sockfd, sa);
        DNS_Reply reply = recv_reply(sockfd, sa);

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
                    no_match = false;
                    break;
                }

                link = link->next;
            }

            if (no_match) {
                // NOTE(ariel) The program failed to match a name server to an
                // IP address.
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
    }

exit:
    arena_release(&g_arena);
    close(sockfd);
    exit(0);
}
