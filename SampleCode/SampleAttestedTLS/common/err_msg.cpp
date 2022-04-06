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

#include "common.h"
#include "sgx_ql_lib_common.h"
#include "sgx_qve_header.h"
#include <map>
#include <string>

/* translate error code here 
 * qv result code and quote3 error code
 */


std::map<quote3_error_t, std::string> ql_error_map =
{
    { SGX_QL_SUCCESS, "quoting service success" },
    { SGX_QL_ERROR_UNEXPECTED, "unexpected error in quoting service"},
    { SGX_QL_OUT_OF_EPC, "not enough EPC to load the quoting enclave"},
    { SGX_QL_ERROR_INVALID_PARAMETER, "invalid parameter"}
};

typedef enum _log_level {
    L_OK = 0,   
    L_WARNING, // log level warning, not fatal
    L_FATAL       // log level fatal
} qv_log_level;

typedef std::pair<qv_log_level, std::string> qv_result_info;

std::string strOK = "SUCCESS:Verification Completed";
std::string strCfgNeeded =
    "quote verification passed, TCB is the latest, still need additional config";
std::string strOutofDate =
    "quote verification passed, TCB level not latest, pls upgrade platform patch";
std::string strOutofDateCfgNeeded =
    "quote verification passed, TCB level out of date, additional config needed at patch level";
std::string strSWHdNeeded =
    "software hardening required";
std::string strInvalidSig =
    "invalid signature over app report";
std::string strRevoked =
    "platform/attestation key is revoked";
std::string strUnspecified =
    "invalid input";


std::map<sgx_ql_qv_result_t, qv_result_info> qve_error_map =
{
    { SGX_QL_QV_RESULT_OK, std::make_pair(L_OK, strOK)},
    { SGX_QL_QV_RESULT_CONFIG_NEEDED, 
        std::make_pair(L_WARNING, strCfgNeeded) },
    { SGX_QL_QV_RESULT_OUT_OF_DATE, 
        std::make_pair(L_WARNING, strOutofDate) },
    { SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED,
        std::make_pair(L_WARNING, strOutofDateCfgNeeded) },
    { SGX_QL_QV_RESULT_SW_HARDENING_NEEDED,
        std::make_pair(L_WARNING, strSWHdNeeded) },
    { SGX_QL_QV_RESULT_INVALID_SIGNATURE,
        std::make_pair(L_FATAL, strInvalidSig) },
    { SGX_QL_QV_RESULT_REVOKED, std::make_pair(L_FATAL, strRevoked) },
    { SGX_QL_QV_RESULT_UNSPECIFIED, std::make_pair(L_FATAL, strUnspecified) }
};


void p_sgx_tls_qv_err_msg(sgx_ql_qv_result_t error_code)
{
    if (qve_error_map.find(error_code) != qve_error_map.end())
    {
        switch (qve_error_map[error_code].first)
        {
            case L_WARNING:
              PRINT("WARNING: 0x%x - %s\n", error_code,
                      qve_error_map[error_code].second.c_str());
              break;
            case L_FATAL:
              PRINT("FATAL: 0x%x - %s\n", error_code,
                      qve_error_map[error_code].second.c_str());
              break;
            default: // default is ok
              // but you need to check the collateral_expiration_status
              // refer to dcap sample qvl(quote_verification_result)
              PRINT("unknown error level\n");
              break;
        }
    }
    else
    {
        PRINT("UNKNOWN error type(0x%x) and info, please check! \n", error_code);
    }
}

void p_sgx_tls_qe_err_msg(quote3_error_t error_code)
{
    if (ql_error_map.find(error_code) != ql_error_map.end())
    {
        PRINT("%s", ql_error_map[error_code].c_str());
    }
    else
    {
        PRINT("please check the error 0x%x\n", error_code);
    }
}
