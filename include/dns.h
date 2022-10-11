#ifndef DNS_H
#define DNS_H

#include "common.h"
#include "str.h"

enum {
    LABEL_SIZE_LIMIT = 64,
    NAME_SIZE_LIMIT  = 64,
    TTL_LIMIT        = INT32_MAX,
    UDP_MSG_LIMIT    = 512,
    DNS_HEADER_LIMIT = 12,
    DNS_DOMAIN_LIMIT = 256,
    DNS_PORT         = 0x3500u,   // NOTE(ariel) Define standard DNS port in network byte order.
};

typedef struct {
    String name;
    u16 type;
    u16 class;
    i32 ttl;
    u16 rdlength;
    u8 *rdata;
} Resource_Record;

typedef struct Resource_Record_Link {
    struct Resource_Record_Link *next;
    Resource_Record rr;
} Resource_Record_Link;

typedef struct {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
} DNS_Header;

typedef struct {
    String domain;
    u16 qtype;
    u16 qclass;
} DNS_Question;

typedef struct {
    DNS_Header header;
    DNS_Question question;
    Resource_Record_Link *answer;
    Resource_Record_Link *authority;
    Resource_Record_Link *additional;
} DNS_Message;
typedef DNS_Message DNS_Query;
typedef DNS_Message DNS_Reply;

void send_query(DNS_Query query, int sockfd, struct sockaddr_in sa);
DNS_Reply recv_reply(int sockfd, struct sockaddr_in sa);

Resource_Record *find_resource_record(Resource_Record_Link *rrs, String name);

#endif
