#ifndef	_SYS_SOCKET_H_
#define	_SYS_SOCKET_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <bits/types.h>
#include <sys/types.h>

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

#ifndef SOCK_STREAM
#define SOCK_STREAM    1
#define SOCK_DGRAM     2
#endif

#define SOCK_RAW       3
#define SOCK_RDM       4
#define SOCK_SEQPACKET 5
#define SOCK_DCCP      6
#define SOCK_PACKET    10

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC   02000000
#define SOCK_NONBLOCK  04000
#endif

#define PF_UNSPEC       0
#define PF_LOCAL        1
#define PF_UNIX         PF_LOCAL
#define PF_FILE         PF_LOCAL
#define PF_INET         2
#define PF_AX25         3
#define PF_IPX          4
#define PF_APPLETALK    5
#define PF_NETROM       6
#define PF_BRIDGE       7
#define PF_ATMPVC       8
#define PF_X25          9
#define PF_INET6        10
#define PF_ROSE         11
#define PF_DECnet       12
#define PF_NETBEUI      13
#define PF_SECURITY     14
#define PF_KEY          15
#define PF_NETLINK      16
#define PF_ROUTE        PF_NETLINK
#define PF_PACKET       17
#define PF_ASH          18
#define PF_ECONET       19
#define PF_ATMSVC       20
#define PF_RDS          21
#define PF_SNA          22
#define PF_IRDA         23
#define PF_PPPOX        24
#define PF_WANPIPE      25
#define PF_LLC          26
#define PF_IB           27
#define PF_MPLS         28
#define PF_CAN          29
#define PF_TIPC         30
#define PF_BLUETOOTH    31
#define PF_IUCV         32
#define PF_RXRPC        33
#define PF_ISDN         34
#define PF_PHONET       35
#define PF_IEEE802154   36
#define PF_CAIF         37
#define PF_ALG          38
#define PF_NFC          39
#define PF_VSOCK        40
#define PF_KCM          41
#define PF_QIPCRTR      42
#define PF_SMC          43
#define PF_XDP          44
#define PF_MAX          45

#define AF_UNSPEC       PF_UNSPEC
#define AF_LOCAL        PF_LOCAL
#define AF_UNIX         AF_LOCAL
#define AF_FILE         AF_LOCAL
#define AF_INET         PF_INET
#define AF_AX25         PF_AX25
#define AF_IPX          PF_IPX
#define AF_APPLETALK    PF_APPLETALK
#define AF_NETROM       PF_NETROM
#define AF_BRIDGE       PF_BRIDGE
#define AF_ATMPVC       PF_ATMPVC
#define AF_X25          PF_X25
#define AF_INET6        PF_INET6
#define AF_ROSE         PF_ROSE
#define AF_DECnet       PF_DECnet
#define AF_NETBEUI      PF_NETBEUI
#define AF_SECURITY     PF_SECURITY
#define AF_KEY          PF_KEY
#define AF_NETLINK      PF_NETLINK
#define AF_ROUTE        PF_ROUTE
#define AF_PACKET       PF_PACKET
#define AF_ASH          PF_ASH
#define AF_ECONET       PF_ECONET
#define AF_ATMSVC       PF_ATMSVC
#define AF_RDS          PF_RDS
#define AF_SNA          PF_SNA
#define AF_IRDA         PF_IRDA
#define AF_PPPOX        PF_PPPOX
#define AF_WANPIPE      PF_WANPIPE
#define AF_LLC          PF_LLC
#define AF_IB           PF_IB
#define AF_MPLS         PF_MPLS
#define AF_CAN          PF_CAN
#define AF_TIPC         PF_TIPC
#define AF_BLUETOOTH    PF_BLUETOOTH
#define AF_IUCV         PF_IUCV
#define AF_RXRPC        PF_RXRPC
#define AF_ISDN         PF_ISDN
#define AF_PHONET       PF_PHONET
#define AF_IEEE802154   PF_IEEE802154
#define AF_CAIF         PF_CAIF
#define AF_ALG          PF_ALG
#define AF_NFC          PF_NFC
#define AF_VSOCK        PF_VSOCK
#define AF_KCM          PF_KCM
#define AF_QIPCRTR      PF_QIPCRTR
#define AF_SMC          PF_SMC
#define AF_XDP          PF_XDP
#define AF_MAX          PF_MAX

#ifndef SO_DEBUG
#define SO_DEBUG        1
#define SO_REUSEADDR    2
#define SO_TYPE         3
#define SO_ERROR        4
#define SO_DONTROUTE    5
#define SO_BROADCAST    6
#define SO_SNDBUF       7
#define SO_RCVBUF       8
#define SO_KEEPALIVE    9
#define SO_OOBINLINE    10
#define SO_NO_CHECK     11
#define SO_PRIORITY     12
#define SO_LINGER       13
#define SO_BSDCOMPAT    14
#define SO_REUSEPORT    15
#define SO_PASSCRED     16
#define SO_PEERCRED     17
#define SO_RCVLOWAT     18
#define SO_SNDLOWAT     19
#define SO_RCVTIMEO     20
#define SO_SNDTIMEO     21
#define SO_ACCEPTCONN   30
#define SO_PEERSEC      31
#define SO_SNDBUFFORCE  32
#define SO_RCVBUFFORCE  33
#define SO_PROTOCOL     38
#define SO_DOMAIN       39
#endif

#define SO_SECURITY_AUTHENTICATION              22
#define SO_SECURITY_ENCRYPTION_TRANSPORT        23
#define SO_SECURITY_ENCRYPTION_NETWORK          24

#define SO_BINDTODEVICE 25

#define SO_ATTACH_FILTER        26
#define SO_DETACH_FILTER        27
#define SO_GET_FILTER           SO_ATTACH_FILTER

#define SO_PEERNAME             28
#define SO_TIMESTAMP            29
#define SCM_TIMESTAMP           SO_TIMESTAMP

#define SO_PASSSEC              34
#define SO_TIMESTAMPNS          35
#define SCM_TIMESTAMPNS         SO_TIMESTAMPNS
#define SO_MARK                 36
#define SO_TIMESTAMPING         37
#define SCM_TIMESTAMPING        SO_TIMESTAMPING
#define SO_RXQ_OVFL             40
#define SO_WIFI_STATUS          41
#define SCM_WIFI_STATUS         SO_WIFI_STATUS
#define SO_PEEK_OFF             42
#define SO_NOFCS                43
#define SO_LOCK_FILTER          44
#define SO_SELECT_ERR_QUEUE     45
#define SO_BUSY_POLL            46
#define SO_MAX_PACING_RATE      47
#define SO_BPF_EXTENSIONS       48
#define SO_INCOMING_CPU         49
#define SO_ATTACH_BPF           50
#define SO_DETACH_BPF           SO_DETACH_FILTER
#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52
#define SO_CNX_ADVICE           53
#define SCM_TIMESTAMPING_OPT_STATS 54
#define SO_MEMINFO              55
#define SO_INCOMING_NAPI_ID     56
#define SO_COOKIE               57
#define SCM_TIMESTAMPING_PKTINFO 58
#define SO_PEERGROUPS           59
#define SO_ZEROCOPY             60

#ifndef SOL_SOCKET
#define SOL_SOCKET      1
#endif

#define SOL_IP          0
#define SOL_IPV6        41
#define SOL_ICMPV6      58

#define SOL_RAW         255
#define SOL_DECNET      261
#define SOL_X25         262
#define SOL_PACKET      263
#define SOL_ATM         264
#define SOL_AAL         265
#define SOL_IRDA        266
#define SOL_NETBEUI     267
#define SOL_LLC         268
#define SOL_DCCP        269
#define SOL_NETLINK     270
#define SOL_TIPC        271
#define SOL_RXRPC       272
#define SOL_PPPOL2TP    273
#define SOL_BLUETOOTH   274
#define SOL_PNPIPE      275
#define SOL_RDS         276
#define SOL_IUCV        277
#define SOL_CAIF        278
#define SOL_ALG         279
#define SOL_NFC         280
#define SOL_KCM         281
#define SOL_TLS         282
#define SOL_XDP         283

#define SOMAXCONN       128

#define MSG_OOB       0x0001
#define MSG_PEEK      0x0002
#define MSG_DONTROUTE 0x0004
#define MSG_CTRUNC    0x0008
#define MSG_PROXY     0x0010
#define MSG_TRUNC     0x0020
#define MSG_DONTWAIT  0x0040
#define MSG_EOR       0x0080
#define MSG_WAITALL   0x0100
#define MSG_FIN       0x0200
#define MSG_SYN       0x0400
#define MSG_CONFIRM   0x0800
#define MSG_RST       0x1000
#define MSG_ERRQUEUE  0x2000
#define MSG_NOSIGNAL  0x4000
#define MSG_MORE      0x8000
#define MSG_WAITFORONE 0x10000
#define MSG_BATCH     0x40000
#define MSG_ZEROCOPY  0x4000000
#define MSG_FASTOPEN  0x20000000
#define MSG_CMSG_CLOEXEC 0x40000000

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char __ss_padding[128-sizeof(long)-sizeof(sa_family_t)];
    unsigned long __ss_align;
};

struct msghdr {
    void *msg_name;       /* optional address */
    socklen_t  msg_namelen;                  /* size of address */
    struct iovec *msg_iov; /* scatter/gather array */
    size_t msg_iovlen;                       /* # elements in msg_iov */
    void *msg_control; /* ancillary data, see below */
    size_t msg_controllen; /* ancillary data buffer len */
    int    msg_flags;      /* flags on received message */
};

// Create a new socket of type TYPE in domain DOMAIN, using protocol PROTOCOL.
// If PROTOCOL is zero, one is chosen automatically.
// Returns a file descriptor for the new socket, or -1 for errors.
int socket (int domain, int type, int protocol);

// Give the socket FD the local address ADDR (which is LEN bytes long)
int bind (int fd, const struct sockaddr *addr, socklen_t len);

// Prepare to accept connections on socket FD.
// N connection requests will be queued before further requests are refused.
// Returns 0 on success, -1 for errors.
int listen (int fd, int n);

// Await a connection on socket FD.
// When a connection arrives, open a new socket to communicate with it,
// set *ADDR (which is *ADDR_LEN bytes long) to the address of the connecting
// peer and *ADDR_LEN to the address's actual length, and return the
// new socket's descriptor, or -1 for errors.
int accept (int fd, struct sockaddr *addr, socklen_t *addr_len);

// Open a connection on socket FD to peer at ADDR (which LEN bytes long).
// For connectionless socket types, just set the default address to send to
// and the only address from which to accept transmissions.
// Return 0 on success, -1 for errors.
int connect (int fd, const struct sockaddr *addr, socklen_t len);

// Send N bytes of BUF to socket FD.
// Returns the number sent or -1.
ssize_t send (int fd, const void *buf, size_t n, int flags);

// Send N bytes of BUF on socket FD to peer at address ADDR (which is
// ADDR_LEN bytes long).
// Returns the number sent, or -1 for errors.
ssize_t sendto (int fd, const void *buf, size_t n, int flags,
                const struct sockaddr *addr, socklen_t addr_len);
/*
 * sendmsg
 * msg - outside enclave
 */
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
// Read N bytes into BUF from socket FD.
// Returns the number read or -1 for errors.
ssize_t recv (int fd, void *buf, size_t n, int flags);

// Read N bytes into BUF through socket FD.
// If ADDR is not NULL, fill in *ADDR_LEN bytes of it with the address of
// the sender, and store the actual size of the address in *ADDR_LEN.
// Returns the number of bytes read or -1 for errors.

ssize_t recvfrom (int fd, void *buf, size_t n, int flags, struct sockaddr *addr,
                  socklen_t *addr_len);

/* 
 * recvmsg
 * msg - outside enclave
 */
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

// Put the current value for socket FD's option OPTNAME at protocol level LEVEL
// into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
// actual length.
// Returns 0 on success, -1 for errors.  */
int getsockopt (int fd, int level, int optname, void *optval, socklen_t *optlen);

// Set socket FD's option OPTNAME at protocol level LEVEL
// to *OPTVAL (which is OPTLEN bytes long).
// Returns 0 on success, -1 for errors.  */
int setsockopt (int fd, int level, int optname, const void *optval,
                socklen_t optlen);

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int socketpair(int domain, int type, int protocol, int retfd[2]);

int shutdown(int sockfd, int how);

#ifdef __cplusplus
}
#endif
#endif
