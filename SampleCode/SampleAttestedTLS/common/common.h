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

#define TLS_CLIENT "TLS client: "
#define TLS_SERVER "TLS server: "

#define CLIENT_PAYLOAD "GET / HTTP/1.0\r\n\r\n"
#define SERVER_PAYLOAD                                   \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection : </p>\r\n"                \
    "A message from TLS server inside enclave\r\n"

#define CLIENT_PAYLOAD_SIZE strlen(CLIENT_PAYLOAD)
#define SERVER_PAYLOAD_SIZE strlen(SERVER_PAYLOAD)



// put common files here in a definition of Macro to reduce
// redundancy code
#ifdef CLIENT_USE_QVL
#include "sgx_utls.h"
#define PRINT printf
#define GETCURRTIME time
#define VERIFY_CALLBACK  tee_verify_certificate_with_evidence_host
#define FREE_SUPDATA tee_free_supplemental_data_host
#else
#include "sgx_ttls.h"
#define PRINT T_PRINT
#define GETCURRTIME T_TIME
#define VERIFY_CALLBACK tee_verify_certificate_with_evidence
#define FREE_SUPDATA tee_free_supplemental_data
#endif

#ifdef TDX_ENV
#define T_PRINT printf
#define T_TIME time
#else
extern void t_print(const char* fmt, ...);
extern void t_time(time_t *c_time);
#define T_PRINT t_print
#define T_TIME t_time
#endif
