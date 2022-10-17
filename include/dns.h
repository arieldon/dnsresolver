#ifndef DNS_H
#define DNS_H

#include <sys/socket.h>

#include "common.h"
#include "str.h"


extern char *const ROOT_SERVER_A_IPv4;
extern char *const ROOT_SERVER_A_IPv6;
extern char *const ROOT_SERVER_E_IPv4;
extern char *const ROOT_SERVER_E_IPv6;


typedef struct sockaddr sockaddr;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_in6 sockaddr_in6;
typedef struct sockaddr_storage sockaddr_storage;


enum {
    LABEL_SIZE_LIMIT = 64,
    NAME_SIZE_LIMIT  = 64,
    TTL_LIMIT        = INT32_MAX,
    UDP_MSG_LIMIT    = 512,
    DNS_HEADER_LIMIT = 12,
    DNS_DOMAIN_LIMIT = 256,
    DNS_PORT         = 0x3500u,   // NOTE(ariel) Define standard DNS port in network byte order.
};

typedef enum {
    DNS_HEADER_FLAG_QR = 0x8000,
    DNS_HEADER_MASK_OP = 0x7800,
    DNS_HEADER_FLAG_AA = 0x0400,
    DNS_HEADER_FLAG_TC = 0x0200,
    DNS_HEADER_FLAG_RD = 0x0100,
    DNS_HEADER_FLAG_RA = 0x0080,
    DNS_HEADER_MASK_Z  = 0x0040,
    DNS_HEADER_MASK_R  = 0x000F,
} DNS_Header_Flags;

typedef enum { RR_CLASS_IN = 1 } RR_Class;

typedef enum {
    RR_TYPE_A      = 1,
    RR_TYPE_NS     = 2,
    RR_TYPE_CNAME  = 5,
    RR_TYPE_AAAA   = 28,
} RR_Type;

extern char *RR_TYPE_STRING[];

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

DNS_Query init_query(char *hostname, RR_Type type);
void send_query(DNS_Query query, int sockfd, sockaddr_storage addr);
DNS_Reply recv_reply(int sockfd, sockaddr_storage addr);

Resource_Record *find_resource_record(Resource_Record_Link *rrs, String name);

#endif
