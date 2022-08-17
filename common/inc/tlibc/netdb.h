// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef	_NETDB_H_
#define	_NETDB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>

struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};

#define AI_PASSIVE      0x01
#define AI_CANONNAME    0x02
#define AI_NUMERICHOST  0x04
#define AI_V4MAPPED     0x08
#define AI_ALL          0x10
#define AI_ADDRCONFIG   0x20
#define AI_NUMERICSERV  0x400


#define NI_NUMERICHOST  0x01
#define NI_NUMERICSERV  0x02
#define NI_NOFQDN       0x04
#define NI_NAMEREQD     0x08
#define NI_DGRAM        0x10
#define NI_NUMERICSCOPE 0x100

#define EAI_BADFLAGS   -1
#define EAI_NONAME     -2
#define EAI_AGAIN      -3
#define EAI_FAIL       -4
#define EAI_FAMILY     -6
#define EAI_SOCKTYPE   -7
#define EAI_SERVICE    -8
#define EAI_MEMORY     -10
#define EAI_SYSTEM     -11
#define EAI_OVERFLOW   -12

/* 
 * getaddrinfo
 * res - [out] inside enclave, *res is outside enclave
 */
int getaddrinfo (const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);

/*
 * freeaddrinfo
 * res - [in] outside enclave
 */
void freeaddrinfo (struct addrinfo *res);

/*
 * getnameinfo
 */
int getnameinfo (const struct sockaddr *sa, socklen_t salen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);

/*
 * gai_strerror
 * return value - outside enclave
 */
const char *gai_strerror(int);

struct hostent {
    char *h_name;
    char **h_aliases;
    int h_addrtype;
    int h_length;
    char **h_addr_list;
};
#define h_addr h_addr_list[0]

#define HOST_NOT_FOUND 1
#define TRY_AGAIN      2
#define NO_RECOVERY    3
#define NO_DATA        4
#define NO_ADDRESS     NO_DATA

#ifdef __cplusplus
}
#endif
#endif
