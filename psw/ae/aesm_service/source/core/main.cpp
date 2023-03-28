/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
#include <signal.h>
#include <unistd.h>
#include <UnixServerSocket.h>
#include <CAESMServer.h>
#include <CSelector.h>
#include <AESMLogicWrapper.h>
#include "quote_ex_service.h"
#include <curl/curl.h>
#include <oal/error_report.h>

#include <SocketConfig.h>

#include <iostream>
#include <getopt.h>

static CAESMServer* server = NULL;
volatile bool reload = false;
// Each bit indicates a certain type of attestation is supported. 
// If a attestation type is marked as supported but AESM fails to load the corresponding module,
// AESM will exit. 
// Currently only two attestation types can be supported: Bit 0: EPID  Bit 1: ECDSA
uint16_t supported_attestation_types = 0;

void signal_handler(int sig)
{
    switch(sig)
    {
        case SIGTERM:
            if (server) 
            {
                reload = false;
                server->shutDown();
            }
            break;
    	case SIGHUP:
            if (server) 
            {
                reload = true;
                server->shutDown();
            }
            break;
        default:
            break;
    }
}

void print_usage() {
    printf("Usage: aesm_service [--no-daemon] [--no-syslog] [--supported_attestation_types=[EPID][,ECDSA]]\n");
}

int main(int argc, char *argv[]) {
    bool noDaemon = false, noSyslog = false;
    int opt= 0;

    //Specifying the expected options
    static struct option long_options[] = {
        {"no-daemon", no_argument, 0, 0 },
        {"no-syslog", no_argument, 0, 1 },
        {"supported_attestation_types", required_argument, 0, 2 },
        {0, 0, 0, 0}
    };

    int long_index =0;
    while ((opt = getopt_long(argc, argv, "012:", long_options, &long_index )) != -1) {
        switch (opt) {
            case 0:
                noDaemon = true;
                break;
            case 1:
                noSyslog = true;
                break;
            case 2:
                if (optarg) {
                    char * token = strtok(optarg, ",");
                    while( token != NULL ) {
                        if (strcasecmp(token, "epid") == 0) {
                            supported_attestation_types |= ATTESTATION_TYPE_EPID;
                        }
                        else if (strcasecmp(token, "ecdsa") == 0) {
                            supported_attestation_types |= ATTESTATION_TYPE_ECDSA;
                        }
                        else {
                            print_usage();
                            exit(EXIT_FAILURE);
                        }
                        token = strtok(NULL, ",");
                    }
                }
                break;
            default:
                print_usage();
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "%s: invalid option -- '%s'\n", argv[0], argv[optind]);
        print_usage();
        exit(EXIT_FAILURE);
    }

    AESM_LOG_INIT_EX(noSyslog);

    if(!noDaemon) {
        fprintf (stderr, "aesm_service: warning: Turn to daemon. Use \"--no-daemon\" option to execute in foreground.\n");
        if(argv[0][0] != '/') {
            AESM_LOG_FATAL("Require absolute path to set daemon.");
            fprintf (stderr, "aesm_service: error: Require absolute path to set daemon.\n");
            AESM_LOG_FINI();
            exit(1);
        }
        if(daemon(0, 0) < 0) {
            AESM_LOG_FATAL("Fail to set daemon.");
            fprintf (stderr, "aesm_service: error: Fail to set daemon.\n");
            AESM_LOG_FINI();
            exit(1);
        }
    }
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, signal_handler);
    //ignore SIGPIPE, socket is unexpectedly closed by client
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, signal_handler);
    try{
    	do{
            reload = false;
            AESMLogicWrapper* aesmLogic = new AESMLogicWrapper();
            if(aesmLogic->service_start()!=AE_SUCCESS){
                AESM_LOG_ERROR("Fail to start service.");
                if(noDaemon) {
                    fprintf (stderr, "aesm_service: error: Fail to start service.\n");
                }
                delete aesmLogic;
                AESM_LOG_FINI();
                exit(1);
            }
            UnixServerSocket* serverSock = new UnixServerSocket(CONFIG_SOCKET_PATH);

            CSelector* selector = new CSelector(serverSock);
            server = new CAESMServer(serverSock, selector, aesmLogic);

            AESM_LOG_WARN("The server sock is %#lx" ,serverSock);   

            server->init();
            server->doWork();
            CAESMServer* temp_server = server;
            server = NULL;
    	    delete temp_server;
        }while(reload == true);
    }
    catch(char const* error_msg)
    {
        AESM_LOG_FATAL("%s", error_msg);
    }

    AESM_LOG_FINI();

    return 0;
}
