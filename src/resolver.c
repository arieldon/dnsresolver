#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "arena.h"
#include "common.h"
#include "dns.h"
#include "err_exit.h"

internal inline void
usage(char *program)
{
    fprintf(stderr, "usage: %s hostname\n", program);
    exit(1);
}

internal DNS_Reply
query(char *server, sockaddr_storage addr, String hostname)
{
    int sockfd = socket(addr.ss_family, SOCK_DGRAM, 0);
    if (sockfd == -1) err_exit("failed to open socket");

    encode_ip(server, &addr);

    send_query(init_query(hostname, addr.ss_family), sockfd, addr);
    DNS_Reply reply = recv_reply(sockfd, addr);

    close(sockfd);
    return reply;
}

internal Resource_Record_List
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
                    Resource_Record_List nameserver = resolve(nameserver_domain);
                    if (nameserver.A) {
                        Resource_Record *rr = &nameserver.A->rr;
                        ip = string_term((String){ .str = rr->rdata, .len = rr->rdlength });
                    } else if (nameserver.AAAA) {
                        Resource_Record *rr = &nameserver.A->rr;
                        ip = string_term((String){ .str = rr->rdata, .len = rr->rdlength });
                    } else err_exit("unable to resolve domain name");
                } else err_exit("unable to resolve domain name");
            }
        } else err_exit("unable to resolve domain name");

        arena_checkpoint_restore(cp);
    }
}

internal void
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

int
main(int argc, char *argv[])
{
    char *program = *argv++;
    if (argc != 2) usage(program);

    arena_init(&g_arena);

    String domain = {
        .str = (u8 *)*argv,
        .len = strlen(*argv),
    };
    output_address(resolve(domain));

    arena_release(&g_arena);
    exit(0);
}
