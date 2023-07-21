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

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "../common/openssl_utility.h"

int set_up_tls_server(char* server_port, bool keep_server_up);

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

int create_listener_socket(int port, int& server_socket)
{
    int ret = -1;
    const int reuse = 1;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        PRINT(TLS_SERVER "socket creation failed\n");
        goto exit;
    }

    if (setsockopt(
            server_socket,
            SOL_SOCKET,
            SO_REUSEADDR,
            (const void*)&reuse,
            sizeof(reuse)) < 0)
    {
        PRINT(TLS_SERVER "setsocket failed \n");
        goto exit;
    }

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        PRINT(TLS_SERVER "Unable to bind socket to the port\n");
        goto exit;
    }

    if (listen(server_socket, 20) < 0)
    {
        PRINT(TLS_SERVER "Unable to open socket for listening\n");
        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

int handle_communication_until_done(
    int& server_socket_fd,
    int& client_socket_fd,
    SSL_CTX*& ssl_server_ctx,
    SSL*& ssl_session,
    bool keep_server_up)
{
    int ret = -1;
	int  test_error = 1;
waiting_for_connection_request:
	
    struct sockaddr_in addr;
    uint len = sizeof(addr);

    // reset ssl_session and client_socket_fd to prepare for the new TLS
    // connection
    if (client_socket_fd > 0) 
    {
        ret = close(client_socket_fd);
        if (ret != 0) {
            PRINT(TLS_SERVER "error closing client socket before starting a new TLS session.\n");
            goto exit;
        }
    }
    SSL_free(ssl_session);
    PRINT(TLS_SERVER " waiting for client connection\n");

    client_socket_fd = accept(server_socket_fd, (struct sockaddr*)&addr, &len);

    if (client_socket_fd < 0)
    {
        PRINT(TLS_SERVER "Unable to accept the client request\n");
        goto exit;
    }

    // create a new SSL structure for a connection
    if ((ssl_session = SSL_new(ssl_server_ctx)) == nullptr)
    {
        PRINT(TLS_SERVER
               "Unable to create a new SSL connection state object\n");
        goto exit;
    }

    SSL_set_fd(ssl_session, client_socket_fd);

    // wait for a TLS/SSL client to initiate a TLS/SSL handshake

    PRINT(TLS_SERVER "initiating a passive connect SSL_accept\n");
    test_error = SSL_accept(ssl_session);
    if (test_error <= 0)
    {
        PRINT(TLS_SERVER " SSL handshake failed, error(%d)(%d)\n",
					test_error, SSL_get_error(ssl_session, test_error));
        goto exit;
    }

    PRINT(TLS_SERVER "<---- Read from client:\n");
    if (read_from_session_peer(
            ssl_session, CLIENT_PAYLOAD, CLIENT_PAYLOAD_SIZE) != 0)
    {
        PRINT(TLS_SERVER " Read from client failed\n");
        goto exit;
    }

    PRINT(TLS_SERVER "<---- Write to client:\n");
    if (write_to_session_peer(
            ssl_session, SERVER_PAYLOAD, strlen(SERVER_PAYLOAD)) != 0)
    {
        PRINT(TLS_SERVER " Write to client failed\n");
        goto exit;
    }

    if (keep_server_up)
        goto waiting_for_connection_request;

    ret = 0;
exit:
    return ret;
}

int set_up_tls_server(char* server_port, bool keep_server_up)
{
    int ret = 0;
    int server_socket_fd;
    int client_socket_fd = -1;
    unsigned int server_port_number;

    X509* certificate = nullptr;
    EVP_PKEY* pkey = nullptr;
    SSL_CONF_CTX* ssl_confctx = SSL_CONF_CTX_new();

    SSL_CTX* ssl_server_ctx = nullptr;
    SSL* ssl_session = nullptr;
    if ((ssl_server_ctx = SSL_CTX_new(TLS_server_method())) == nullptr)
    {
        PRINT(TLS_SERVER "unable to create a new SSL context\n");
        goto exit;
    }

    if (initalize_ssl_context(ssl_confctx, ssl_server_ctx) != SGX_SUCCESS)
    {
        PRINT(TLS_SERVER "unable to create a initialize SSL context\n ");
        goto exit;
    }
    SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER, &verify_callback);
    
    if (load_tls_certificates_and_keys(ssl_server_ctx, certificate, pkey) != 0)
    {
        PRINT(TLS_SERVER
               " unable to load certificate and private key on the server\n ");
        goto exit;
    }
	
    server_port_number = (unsigned int)atoi(server_port); // convert to char* to int
    if (create_listener_socket(server_port_number, server_socket_fd) != 0)
    {
        PRINT(TLS_SERVER " unable to create listener socket on the server\n ");
        goto exit;
    }

    // handle communication
    ret = handle_communication_until_done(
        server_socket_fd,
        client_socket_fd,
        ssl_server_ctx,
        ssl_session,
        keep_server_up);
    if (ret != 0)
    {
        PRINT(TLS_SERVER "server communication error %d\n", ret);
        goto exit;
    }

exit:
    ret = close(client_socket_fd); // close the socket connections
    if (ret != 0)
        PRINT(TLS_SERVER "error closing client socket\n");
    ret = close(server_socket_fd);
    if (ret != 0)
        PRINT(TLS_SERVER "error closing server socket\n");

    if (ssl_session)
    {
        SSL_shutdown(ssl_session);
        SSL_free(ssl_session);
    }
    if (ssl_server_ctx)
        SSL_CTX_free(ssl_server_ctx);
    if (ssl_confctx)
        SSL_CONF_CTX_free(ssl_confctx);
    if (certificate)
        X509_free(certificate);
    if (pkey)
        EVP_PKEY_free(pkey);
    return (ret);
}
