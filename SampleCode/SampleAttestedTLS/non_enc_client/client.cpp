/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sgx_utls.h"
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "../common/common.h"

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
int create_socket(char* server_name, char* server_port);

int parse_arguments(
    int argc,
    char** argv,
    char** server_name,
    char** server_port)
{
    int ret = 1;
    const char* option = nullptr;
    unsigned int param_len = 0;

    if (argc != 3)
        goto print_usage;

    option = "-server:";
    param_len = strlen(option);
    if (strncmp(argv[1], option, param_len) != 0)
        goto print_usage;
    *server_name = (char*)(argv[1] + param_len);

    option = "-port:";
    param_len = strlen(option);
    if (strncmp(argv[2], option, param_len) != 0)
        goto print_usage;

    *server_port = (char*)(argv[2] + param_len);
    ret = 0;
    goto done;

print_usage:
    printf(TLS_CLIENT "Usage: %s -server:<name> -port:<port>\n", argv[0]);
done:
    return ret;
}

// This routine conducts a simple HTTP request/response communication with
// server
int communicate_with_server(SSL* ssl)
{
    unsigned char buf[200];
    int ret = 1;
    int error = 0;
    unsigned int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;

    // Write an GET request to the server
    printf(TLS_CLIENT "-----> Write to server:\n");
    len = snprintf((char*)buf, sizeof(buf) - 1, CLIENT_PAYLOAD);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto done;
    }

    printf(TLS_CLIENT "%d bytes written\n", bytes_written);

    // Read the HTTP response from server
    printf(TLS_CLIENT "<---- Read from server:\n");
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl, buf, (size_t)len);
        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf(TLS_CLIENT "Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            goto done;
        }

        printf(TLS_CLIENT " %d bytes read\n", bytes_read);
        
        // check to to see if received payload is expected
        if ((bytes_read != SERVER_PAYLOAD_SIZE) ||
            (memcmp(SERVER_PAYLOAD, buf, bytes_read) != 0))
        {
            printf(
                TLS_CLIENT "ERROR: expected reading %lu bytes but only "
                           "received %d bytes\n",
                SERVER_PAYLOAD_SIZE,
                bytes_read);
            ret = bytes_read;
            goto done;
        }
        else
        {
            printf(TLS_CLIENT
                   " received all the expected data from server\n\n");
            ret = 0;
            printf("Verified: the contents of server payload were expected\n\n");
            break;
        }
    } while (1);
    ret = 0;
done:
    return ret;
}

// create a socket and connect to the server_name:server_port
int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
    struct addrinfo hints, *dest_info, *curr_di;
    int res;

    hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((res = getaddrinfo(server_name, server_port, &hints, &dest_info)) != 0)
    {
        printf(
            TLS_CLIENT "Error: Cannot resolve hostname %s. %s\n",
            server_name,
            gai_strerror(res));
        goto done;
    }

    curr_di = dest_info;
    while (curr_di)
    {
        if (curr_di->ai_family == AF_INET)
        {
            break;
        }

        curr_di = curr_di->ai_next;
    }

    if (!curr_di)
    {
        printf(
            TLS_CLIENT "Error: Cannot get address for hostname %s.\n",
            server_name);
        goto done;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    if (connect(
            sockfd,
            (struct sockaddr*)curr_di->ai_addr,
            sizeof(struct sockaddr)) == -1)
    {
        printf(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_name,
            server_port,
            errno);
        close(sockfd);
        sockfd = -1;
        goto done;
    }
    printf(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

done:
    if (dest_info)
        freeaddrinfo(dest_info);

    return sockfd;
}

int main(int argc, char** argv)
{
    int ret = 1;
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    int serversocket = 0;
    char* server_name = nullptr;
    char* server_port = nullptr;
    int error = 0;

    printf("\nStarting" TLS_CLIENT "\n\n\n");
    if ((error = parse_arguments(argc, argv, &server_name, &server_port)) != 0)
    {
        printf(
            TLS_CLIENT "TLS client:parse input parmeter failed (%d)!\n", error);
        goto done;
    }

    // initialize openssl library and register algorithms
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0)
    {
        printf(TLS_CLIENT
               "TLS client: could not initialize the OpenSSL library !\n");
        goto done;
    }

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == nullptr)
    {
        printf(TLS_CLIENT "TLS client: unable to create a new SSL context\n");
        goto done;
    }

    // choose TLSv1.2 by excluding SSLv2, SSLv3 ,TLS 1.0 and TLS 1.1
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &verify_callback);
    
    if ((ssl = SSL_new(ctx)) == nullptr)
    {
        printf(TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto done;
    }

    serversocket = create_socket(server_name, server_port);
    if (serversocket == -1)
    {
        printf(
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    printf(
            TLS_CLIENT
            "create a socket and initate a TCP connect to server: %s:%s "
            "\n",
            server_name,
            server_port);
    // setup ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl, serversocket);
    if ((error = SSL_connect(ssl)) != 1)
    {
        printf(
            TLS_CLIENT "Error: Could not establish an SSL session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl, error));
        goto done;
    }
    printf(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl));

    // start the client server communication
    if ((error = communicate_with_server(ssl)) != 0)
    {
        printf(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
        goto done;
    }

    // Free the structures we don't need anymore
    ret = 0;
done:
    if (serversocket != -1)
        close(serversocket);

    if (ssl)
        SSL_free(ssl);

    if (ctx)
        SSL_CTX_free(ctx);

    printf(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
}
