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

#include "sgx_urts.h"
#include <stdio.h>
#include <netdb.h>
#include "tls_client_u.h"
#include <sys/socket.h>
#include <sys/types.h>

#define TLS_SERVER_NAME "localhost"
#define TLS_SERVER_PORT "12340"

/* Global EID shared by multiple threads */
sgx_enclave_id_t client_global_eid = 0;


typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

sgx_status_t initialize_enclave(const char *enclave_path)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	// the 1st parameter should be CLIENT_ENCLAVE_FILENAME
	ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, &client_global_eid, NULL);
    printf("Client Enc: Enclave library %s\n", enclave_path);

    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return ret;
    }
    return ret;
}

void terminate_enclave()
{
	sgx_destroy_enclave(client_global_eid);
    printf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char* argv[])
{
    sgx_status_t result = SGX_SUCCESS;
    int ret = 1;
    char* server_name = NULL;
    char* server_port = NULL;

    /* Check argument count */
    if (argc != 4)
    {
    print_usage:
        printf(
            "Usage: %s TLS_SERVER_ENCLAVE_PATH -server:<name> -port:<port>\n",
            argv[0]);
        return 1;
    }
    // read server name  parameter
    {
        const char* option = "-server:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[2], option, param_len) == 0)
        {
            server_name = (char*)(argv[2] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }
    printf("server name = [%s]\n", server_name);

    // read port parameter
    {
        const char* option = "-port:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[3], option, param_len) == 0)
        {
            server_port = (char*)(argv[3] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }
    printf("server port = [%s]\n", server_port);

    printf("Host: Creating client enclave\n");
    result = initialize_enclave(argv[1]);
    if (result != SGX_SUCCESS)
    {
        goto exit;
    }

    printf("Host: launch TLS client to initiate TLS connection\n");
    result = launch_tls_client(client_global_eid, &ret, server_name, server_port);
    if (result != SGX_SUCCESS || ret != 0)
    {
        printf("Host: launch_tls_client failed\n");
        goto exit;
    }
    ret = 0;
exit:

    terminate_enclave();

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
