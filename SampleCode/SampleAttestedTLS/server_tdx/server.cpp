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

#include <stdio.h>
#include <string.h>

#define LOOP_OPTION "-server-in-loop"

int set_up_tls_server(char* server_port, bool keep_server_up);

int main(int argc, const char* argv[])
{
    int ret = 1;
    char* server_port = NULL;
    int keep_server_up = 0; // should be bool type, 0 false, 1 true

    /* Check argument count */
    if (argc != 2)
    {
        if (argc == 3)
        {
            if (strcmp(argv[2], LOOP_OPTION) != 0)
            {
                goto print_usage;
            }
            else
            {
                keep_server_up = 1;
                goto read_port;
            }
        }
    print_usage:
        printf(
            "Usage: %s -port:<port> [%s]\n",
            argv[0],
            LOOP_OPTION);
        return 1;
    }

read_port:
    // read port parameter
    {
        char* option = (char*)"-port:";
        size_t param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[1], option, param_len) == 0)
        {
            server_port = (char*)(argv[1] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[1]);
            goto print_usage;
        }
    }
    printf("server port = %s\n", server_port);

    printf("Host: calling setup_tls_server\n");
    ret = set_up_tls_server(server_port, keep_server_up);
    if (ret != 0)
    {
        printf("Host: setup_tls_server failed\n");
        goto exit;
    }

exit:
    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
