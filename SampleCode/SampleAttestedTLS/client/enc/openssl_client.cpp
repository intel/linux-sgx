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

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <string.h>
#include "../../common/openssl_utility.h"
#include "tls_client_t.h"
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>


int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

extern "C"
{
    int launch_tls_client(char* server_name, char* server_port);
};


unsigned long inet_addr2(const char *str)
{
    unsigned long lHost = 0;
    char *pLong = (char *)&lHost;
    char *p = (char *)str;
    while (p)
    {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p)
            ++p;
    }
    return lHost;
}
// This routine conducts a simple HTTP request/response communication with
// server
int communicate_with_server(SSL* ssl)
{
    unsigned char buf[200];
    int ret = 1;
    int error = 0;
    int len = 0;
    int bytes_written = 0;
    int bytes_read = 0;

    // Write an GET request to the server
    t_print(TLS_CLIENT "-----> Write to server:\n");
    len = snprintf((char*)buf, sizeof(buf) - 1, CLIENT_PAYLOAD);
    while ((bytes_written = SSL_write(ssl, buf, (size_t)len)) <= 0)
    {
        error = SSL_get_error(ssl, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        t_print(TLS_CLIENT "Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto done;
    }

    t_print(TLS_CLIENT "%d bytes written\n", bytes_written);

    // Read the HTTP response from server
    t_print(TLS_CLIENT "<---- Read from server:\n");
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

            t_print(TLS_CLIENT "Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        t_print(TLS_CLIENT " %d bytes read\n", bytes_read);
        // check to to see if received payload is expected
        if ((bytes_read != SERVER_PAYLOAD_SIZE) ||
            (memcmp(SERVER_PAYLOAD, buf, bytes_read) != 0))
        {
            t_print(
                TLS_CLIENT "ERROR: expected reading %lu bytes but only "
                           "received %d bytes\n",
                SERVER_PAYLOAD_SIZE,
                bytes_read);
            ret = bytes_read;
            break;
        }
        else
        {
            t_print(TLS_CLIENT
                   " received all the expected data from server\n\n");
            ret = 0;
            break;
        }
    } while (1);
done:
    return ret;
}

// create a socket and connect to the server_name:server_port
int create_socket(char* server_name, char* server_port)
{
    int sockfd = -1;
	struct sockaddr_in dest_sock;
    int res = -1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        t_print(TLS_CLIENT "Error: Cannot create socket %d.\n", errno);
        goto done;
    }

    dest_sock.sin_family = AF_INET;
    dest_sock.sin_port = htons(atoi(server_port));
    dest_sock.sin_addr.s_addr = inet_addr2(server_name);
    bzero(&(dest_sock.sin_zero), sizeof(dest_sock.sin_zero));
    
    if (connect(
                sockfd, (sockaddr*) &dest_sock,
                sizeof(struct sockaddr)) == -1)
    {
        t_print(
            TLS_CLIENT "failed to connect to %s:%s (errno=%d)\n",
            server_port,
            server_port,
            errno);
        ocall_close(&res, sockfd);
        if (res != 0)
            t_print(TLS_CLIENT "OCALL: error closing socket\n");
        sockfd = -1;
        goto done;
    }
    t_print(TLS_CLIENT "connected to %s:%s\n", server_name, server_port);

done:
    return sockfd;
}

int launch_tls_client(char* server_name, char* server_port)
{
    t_print(TLS_CLIENT " called launch tls client\n");

    int ret = 0;

    SSL_CTX* ssl_client_ctx = nullptr;
    SSL* ssl_session = nullptr;

    X509* cert = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    int client_socket = -1;
    int error = 0;

    t_print("\nStarting" TLS_CLIENT "\n\n\n");

    if ((ssl_client_ctx = SSL_CTX_new(TLS_client_method())) == nullptr)
    {
        t_print(TLS_CLIENT "unable to create a new SSL context\n");
        goto done;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_client_ctx) != SGX_SUCCESS)
    {
        t_print(TLS_CLIENT "unable to create a initialize SSL context\n ");
        goto done;
    }

    // specify the verify_callback for custom verification
    SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, &verify_callback);
	t_print(TLS_CLIENT "load cert and key\n");
    if (load_tls_certificates_and_keys(ssl_client_ctx, cert, pkey) != 0)
    {
        t_print(TLS_CLIENT
               " unable to load certificate and private key on the client\n");
        goto done;
    }
	
    if ((ssl_session = SSL_new(ssl_client_ctx)) == nullptr)
    {
        t_print(TLS_CLIENT
               "Unable to create a new SSL connection state object\n");
        goto done;
    }

    t_print(TLS_CLIENT "new ssl connection getting created\n");
    client_socket = create_socket(server_name, server_port);
    if (client_socket == -1)
    {
        t_print(
            TLS_CLIENT
            "create a socket and initiate a TCP connect to server: %s:%s "
            "(errno=%d)\n",
            server_name,
            server_port,
            errno);
        goto done;
    }

    // set up ssl socket and initiate TLS connection with TLS server
    SSL_set_fd(ssl_session, client_socket);

    if ((error = SSL_connect(ssl_session)) != 1)
    {
        t_print(
            TLS_CLIENT "Error: Could not establish a TLS session ret2=%d "
                       "SSL_get_error()=%d\n",
            error,
            SSL_get_error(ssl_session, error));
        goto done;
    }
    t_print(
        TLS_CLIENT "successfully established TLS channel:%s\n",
        SSL_get_version(ssl_session));

    // start the client server communication
    if ((error = communicate_with_server(ssl_session)) != 0)
    {
        t_print(TLS_CLIENT "Failed: communicate_with_server (ret=%d)\n", error);
        goto done;
    }

    // Free the structures we don't need anymore
    ret = 0;
done:

    if (client_socket != -1) 
    {
        ocall_close(&ret, client_socket);
        if (ret != 0)
            t_print(TLS_CLIENT "OCALL: error close socket\n");
    }

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }

    if (cert)
        X509_free(cert);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (ssl_client_ctx)
        SSL_CTX_free(ssl_client_ctx);

    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);

    t_print(TLS_CLIENT " %s\n", (ret == 0) ? "success" : "failed");
    return (ret);
}
