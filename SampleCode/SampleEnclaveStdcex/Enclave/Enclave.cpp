/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>
#include <mbusafecrt.h>
#include "zlib.h"
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include "sgx_thread.h"

#include <ctype.h>
#include <sys/types.h>
//#include <arpa/inet.h>
//#include <winsock2.h>

//#include "se_memory.h"
//#include "se_trace.h"
//#include "util.h"
#include <sys/mman.h>

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        return -1; \
    } \
}

static z_const char hello[] = "hello, hello!";

#define TEST_PATH_MAX 1024
static const mode_t MODE = 0644;


void ecall_printf()
{
    printf("Printing by the printf() from the SDK.\n");
    return;
}

int ecall_memset_s()
{
    char str[15] = {0};
    if ( 0 != memset_s(str, sizeof(str), 'b', sizeof(str)-1)) return -1;
    printf("After setting buffer with memset_s(): %s.\n", str);
    return 0;
}

int ecall_fchmod()
{
    int fd;
    char oldname[TEST_PATH_MAX] = "/tmp/testfile.txt";

    const int flags = O_CREAT | O_TRUNC | O_WRONLY;
    if((fd = open(oldname, flags, MODE)) == -1)
        return -2;

    if (fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH) != 0)
    {
    printf("fchmod fail, errno is %d\n", errno);
        printf("fchmod(): FAIL\n");
        return -3;
    }
    else
        printf("fchmod(): PASS\n");

    close(fd);
    return 0;
}

int test_compress(Byte *compr, uLong comprLen, Byte *uncompr, uLong uncomprLen)
{
    int err;
    uLong len = (uLong)strlen(hello)+1;

    err = compress(compr, &comprLen, (const Bytef*)hello, len);
    CHECK_ERR(err, "compress");

    strncpy_s((char*)uncompr, strlen((char*)uncompr), "garbage", strlen("garbage"));

    err = uncompress(uncompr, &uncomprLen, compr, comprLen);
    CHECK_ERR(err, "uncompress");

    if (strcmp((char*)uncompr, hello)) {
        fprintf(stderr, "bad uncompress\n");
        return -1;
    } else {
        printf("uncompress(): %s\n", (char *)uncompr);
    }
    return 0;
}

int ecall_compress()
{
    Byte *compr, *uncompr;
    uLong comprLen = 10000*sizeof(int);
    uLong uncomprLen = comprLen;

    compr    = (Byte*)calloc((uInt)comprLen, 1);
    uncompr  = (Byte*)calloc((uInt)uncomprLen, 1);
    /* compr and uncompr are cleared to avoid reading uninitialized
     * data and to ensure that uncompr compresses well.
     */
    if (compr == Z_NULL || uncompr == Z_NULL) {
        printf("out of memory\n");
        return -1;
    }

    return test_compress(compr, comprLen, uncompr, uncomprLen);
}

int ecall_time()
{
    time_t tloc;
    time(&tloc);
    if (-1 == tloc)
    {
        printf("can't get the time\n");
        return -1;
    }
    printf("time(): Since 1st January 1970 UTC, %d seconds or %d days passed\n",(int)tloc,(int)tloc/86400);
    return 0;
}

void ecall_socket_receiver()
{
    int sockfd = 0;
    char recv_buff[1024]={0};
    size_t buff_len = 1024;
    struct sockaddr_in serv_addr = {0};

    printf("CLIENT: create socket\n");
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n CLIENT: Could not create socket \n");
        abort();
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1492);

    printf("CLIENT: socket fd = %d\n", sockfd);
    printf("CLIENT: connecting...\n");
    int retries = 0;
    static const int max_retries = 4;

    while (connect(
               sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
    {
        if (retries++ > max_retries)
        {
            printf("\n CLIENT: Connect Failed \n");
            close(sockfd);
            abort();
        }
        else
        {
            printf("CLIENT: Connect Failed. Retrying... \n");
        }
    }

    printf("CLIENT: reading...\n");

    size_t nread = 0;

    struct timeval tv;
    fd_set rfds;
    int nfds = 1;
    while(1) {
        int ready = -1, ready_for_recv = 0;
        ssize_t nbytes;

        nfds = sockfd+1;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        FD_CLR(0,&rfds);
        FD_SET(sockfd, &rfds);

        ready = select(nfds, &rfds, NULL, NULL, &tv);

        if (ready == -1 && errno == EINTR)
            continue;

        if (ready == -1)
        {
            printf("CLIENT: ERROR select\n");
            close(sockfd);
            abort();
        }
        ready_for_recv = FD_ISSET(sockfd, &rfds);

        if (ready_for_recv) {
            nbytes = recv(sockfd, recv_buff + nread, buff_len - nread, 0);

            if (nbytes < 0)
            {
                printf("CLIENT: ERROR recv\n");
                break;
            }
            else if (nbytes == 0)
            {
                printf("CLIENT: finished reading of %ld bytes\n", nread);
                break;
            }
            else
            {
                printf("CLIENT: recv %ld bytes : %s", nbytes, recv_buff);
                nread += (size_t)nbytes;
            }
        }
    }

    /* Make sure shutdown call also works. */
    if (shutdown(sockfd, SHUT_RDWR) != 0) abort();

    printf("CLIENT: closing...\n");
    close(sockfd);
    return ;
}


void ecall_socket_sender()
{
    static const char TESTDATA[] = "This is TEST DATA\n";
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    int connfd = 0;
    struct sockaddr_in serv_addr = {0};

    const int optVal = 1;
    const socklen_t optLen = sizeof(optVal);

    int rtn =
            setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void*)&optVal, optLen);
    if (rtn > 0)
    {
            printf("SERVER: setsockopt failed return = %d\n", rtn);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    serv_addr.sin_port = htons(1492);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

    while (1)
    {
        printf("SERVER: accepting...\n");
        connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);

        printf("SERVER: accept fd = %d\n", connfd);
        if (connfd >= 0)
        {
            printf("SERVER: send %d bytes\ : %s", strlen(TESTDATA), TESTDATA);
            ssize_t n = send(connfd, TESTDATA, strlen(TESTDATA), 0);
            if ((size_t)n == strlen(TESTDATA))
            {
                printf("SERVER: send complete\n");
            }
            else
            {
                printf("SERVER: send failed\n");
            }
            close(connfd);
            break;
        }
    }

    printf("SERVER: closing\n");
    close(listenfd);

    return;
}
int test_mmap(void* address, size_t size)
{
    int mmap_flag = MAP_PRIVATE |  MAP_ANONYMOUS;
    if(address != NULL)
    mmap_flag |= MAP_FIXED;
    void* pRet = mmap(address, size, PROT_READ | PROT_WRITE, mmap_flag, -1, 0);
    if(MAP_FAILED == pRet)
        return 1;
    return 0;
}

int  ecall_mmap()
{
    int ret;
    ret = test_mmap(NULL,0x100);
    if (ret ==1)
    {
        printf("fail to mmap");
        return 1;
    }
    printf("mmap(): PASS\n");
    return 0;
}
