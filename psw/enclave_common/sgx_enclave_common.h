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

#ifndef _SGX_ENCLAVE_COMMON_H_
#define _SGX_ENCLAVE_COMMON_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <sal.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
/* The following macros are MSVC only */
#define COMM_API cdecl
#define COMM_IN _In_
#define COMM_IN_OPT _In_opt_
#define COMM_OUT _Out_
#define COMM_OUT_OPT _Out_opt_
#define COMM_IN_OUT _Inout_
#else
/* The following macros are for GCC only */
#define COMM_API
#define COMM_IN
#define COMM_IN_OPT
#define COMM_OUT
#define COMM_OUT_OPT
#define COMM_IN_OUT
#endif

#ifndef ENCLAVE_TYPE_SGX
#define ENCLAVE_TYPE_SGX            0x00000001    /* An enclave for the Intel Software Guard Extensions (SGX) architecture version 1. */
#endif
#ifndef ENCLAVE_TYPE_SGX2
#define ENCLAVE_TYPE_SGX2           0x00000002    /* An enclave for the Intel Software Guard Extensions (SGX) architecture version 2. */
#endif
#define ENCLAVE_TYPE_SGX1 ENCLAVE_TYPE_SGX


#define ENCLAVE_MK_ERROR(x) (0x00000000 | (x))

typedef enum {
    ENCLAVE_ERROR_SUCCESS = ENCLAVE_MK_ERROR(0x0000),       /* No error. */
    ENCLAVE_NOT_SUPPORTED = ENCLAVE_MK_ERROR(0x0001),       /* Enclave type not supported, Intel® SGX is not supported, the Intel® SGX device is not present, or the AESM Service is not running. */
    ENCLAVE_INVALID_SIG_STRUCT = ENCLAVE_MK_ERROR(0x0002),  /* SGX - SIGSTRUCT contains an invalid value. */
    ENCLAVE_INVALID_SIGNATURE = ENCLAVE_MK_ERROR(0x0003),   /* SGX – invalid Signature or SIGSTRUCT. */
    ENCLAVE_INVALID_ATTRIBUTE = ENCLAVE_MK_ERROR(0x0004),   /* SGX – invalid SECS Attribute. */
    ENCLAVE_INVALID_MEASUREMENT = ENCLAVE_MK_ERROR(0x0005), /* SGX – invalid measurement. */
    ENCLAVE_NOT_AUTHORIZED = ENCLAVE_MK_ERROR(0x0006),      /* Enclave not authorized to run,  .e.g. provisioning enclave hosted in an app without access rights to /dev/sgx_provision */
    ENCLAVE_INVALID_ENCLAVE = ENCLAVE_MK_ERROR(0x0007),     /* Address is not a Valid Enclave. */
    ENCLAVE_LOST = ENCLAVE_MK_ERROR(0x0008),                /* SGX – enclave is lost (likely due to a power event). */
    ENCLAVE_INVALID_PARAMETER = ENCLAVE_MK_ERROR(0x0009),   /* Invalid Parameter (unspecified) – may be due to type length/format. */
    ENCLAVE_OUT_OF_MEMORY = ENCLAVE_MK_ERROR(0x000a),
    ENCLAVE_DEVICE_NO_RESOURCES = ENCLAVE_MK_ERROR(0x000b), /* Out of EPC Memory. */
    ENCLAVE_ALREADY_INITIALIZED = ENCLAVE_MK_ERROR(0x000c), /* Enclave has already been initialized. */
    ENCLAVE_INVALID_ADDRESS = ENCLAVE_MK_ERROR(0x000d),     /* Address is not within a valid enclave./ Address has already been committed. */
    ENCLAVE_RETRY = ENCLAVE_MK_ERROR(0x000e),               /* Please retry the operation – there was an unmasked event in EINIT. */
    ENCLAVE_INVALID_SIZE = ENCLAVE_MK_ERROR(0x000f),        /* An invalid size was entered. */
    ENCLAVE_NOT_INITIALIZED = ENCLAVE_MK_ERROR(0x0010),     /* The enclave is not initialized – the operation requires that the enclave be initialized. */
    ENCLAVE_SERVICE_TIMEOUT = ENCLAVE_MK_ERROR(0x0011),     /* The launch service timed out when attempting to obtain a launch token.  Check to ensure that the AESM service is running and accessible. */
    ENCLAVE_SERVICE_NOT_AVAILABLE = ENCLAVE_MK_ERROR(0x0012), /* The launch service is not available when attempting to obtain a launch token.  Check to ensure that the AESM service is running. */
    ENCLAVE_MEMORY_MAP_FAILURE = ENCLAVE_MK_ERROR(0x0013),  /* Failed to reserve memory for the enclave. */
    ENCLAVE_UNEXPECTED = ENCLAVE_MK_ERROR(0x1001),          /* Unexpected error. */
} enclave_error_t;

typedef enum {
    ENCLAVE_PAGE_READ = 1 << 0,           /* Enables read access to the committed region of pages. */
    ENCLAVE_PAGE_WRITE = 1 << 1,          /* Enables write access to the committed region of pages. */
    ENCLAVE_PAGE_EXECUTE = 1 << 2,        /* Enables execute access to the committed region of pages. */
    ENCLAVE_PAGE_THREAD_CONTROL = 1 << 8, /* The page contains a thread control structure. */
    ENCLAVE_PAGE_REG = 2 << 8,            /* The page contains a PT_REG page. */
    ENCLAVE_PAGE_TRIM = 4 << 8,           /* The page is trimmed(PT_TRIM). This is for pages which will be trimmed (removed) from the enclave. */
    ENCLAVE_PAGE_SS_FIRST = 5 << 8,       /* The page contains the first page of a Shadow Stack (future). */
    ENCLAVE_PAGE_SS_REST = 6 << 8,        /* The page contains a non-first page of a Shadow Stack (future). */
    ENCLAVE_PAGE_UNVALIDATED = 1 << 12,   /* The page contents that you supply are excluded from measurement and content validation. */
} enclave_page_properties_t;

/*
 * Hints to OS on how application may use the pages allocated with enclave_alloc.
 */
typedef enum {
    ENCLAVE_EMA_NONE = 0,                /* No suggestions provided. */
    ENCLAVE_EMA_RESERVE = 1,             /* Suggest that the kernel should reserve the memory range and not immediately EAUG pages. */
    ENCLAVE_EMA_COMMIT_NOW = 2,          /* Gives a hint that the kernel should EAUG pages immediately. */
    ENCLAVE_EMA_COMMIT_ON_DEMAND  = 4,   /* Gives a hint that the kernel can EAUG pages later. */
    ENCLAVE_EMA_GROWSDOWN = 16,          /* Gives a hint to the kernel that the application will access pages above the
                                            last accessed page.  The kernel may want to EAUG pages from higher to lower addresses
                                            with no gaps in addresses above the last committed page. */
    ENCLAVE_EMA_GROWSUP = 32,            /* Gives a hint to the kernel that the application will access pages below the
                                            last accessed page.  The kernel may want to EAUG pages from lower to higher addresses
                                            with no gaps in addresses below the last committed page. */
} enclave_alloc_flags_t;

typedef enum {
    ENCLAVE_LAUNCH_TOKEN = 0x1
} enclave_info_type_t;


#define ENCLAVE_CREATE_MAX_EX_FEATURES_COUNT    32

#define ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX      0
#define ENCLAVE_CREATE_EX_EL_RANGE              (1 << ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX) // Reserve Bit 0 for the el_range config

//update the following when adding new extended feature
#define _ENCLAVE_CREATE_LAST_EX_FEATURE_IDX_  ENCLAVE_CREATE_EX_EL_RANGE_BIT_IDX

#define _ENCLAVE_CREATE_EX_FEATURES_MASK_ (((uint32_t)-1) >> (ENCLAVE_CREATE_MAX_EX_FEATURES_COUNT - 1  - _ENCLAVE_CREATE_LAST_EX_FEATURE_IDX_))


typedef struct enclave_elrange {
    uint64_t enclave_image_address;
    uint64_t elrange_start_address;
    uint64_t elrange_size;
}enclave_elrange_t;

#define SECS_SIZE 4096
#define SIGSTRUCT_SIZE 1808

typedef struct enclave_create_sgx_t {
    uint8_t secs[SECS_SIZE];
} enclave_create_sgx_t;

typedef struct enclave_init_sgx_t {
    uint8_t sigstruct[SIGSTRUCT_SIZE];
} enclave_init_sgx_t;


/* enclave_create_ex()
 * Parameters:
 *      base_address [in, optional] - An optional preferred base address for the enclave.
 *      virtual_size [in] - The virtual address range of the enclave in bytes.
 *      initial_commit[in] - The amount of physical memory to reserve for the initial load of the enclave in bytes.
 *      type [in] - The architecture type of the enclave that you want to create.
 *      info [in] - A pointer to the architecture-specific information to use to create the enclave.
 *      info_size [in] - The length of the structure that the info parameter points to, in bytes.
 *      ex_features [in] - Bitmask defining the extended features to activate on the enclave creation.
 *      ex_features_p [in] - Array of pointers to extended feature control structures.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      If the function succeeds, the return value is the base address of the created enclave.
 *      If the function fails, the return value is NULL. The extended error information will be in the enclave_error parameter if used.
*/
void* COMM_API enclave_create_ex(
    COMM_IN_OPT void* base_address,
    COMM_IN size_t virtual_size,
    COMM_IN size_t initial_commit,
    COMM_IN uint32_t type,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_IN const uint32_t ex_features,
    COMM_IN const void* ex_features_p[32],
    COMM_OUT_OPT uint32_t* enclave_error);


/* enclave_create()
 * Parameters:
 *      base_address [in, optional] - An optional preferred base address for the enclave.
 *      virtual_size [in] - The virtual address range of the enclave in bytes.
 *      initial_commit[in] - The amount of physical memory to reserve for the initial load of the enclave in bytes.
 *      type [in] - The architecture type of the enclave that you want to create.
 *      info [in] - A pointer to the architecture-specific information to use to create the enclave.
 *      info_size [in] - The length of the structure that the info parameter points to, in bytes.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      If the function succeeds, the return value is the base address of the created enclave.
 *      If the function fails, the return value is NULL. The extended error information will be in the enclave_error parameter if used.
*/
void* COMM_API enclave_create(
    COMM_IN_OPT void* base_address,
    COMM_IN size_t virtual_size,
    COMM_IN size_t initial_commit,
    COMM_IN uint32_t type,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_load_data()
 * Parameters:
 *      target_address [in] - The address in the enclave where you want to load the data.
 *      target_size [in] - The size of the range that you want to load in the enclave, in bytes.
 *      source_buffer [in, optional] - An optional pointer to the data you want to load into the enclave.
 *      data_properties [in] - The properties of the pages you want to add to the enclave.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      The return value is the number of bytes that was loaded into the enclave.
 *      If the number is different than target_size parameter an error occurred. The extended error information will be in the enclave_error parameter if used.
*/
size_t COMM_API enclave_load_data(
    COMM_IN void* target_address,
    COMM_IN size_t target_size,
    COMM_IN_OPT const void* source_buffer,
    COMM_IN uint32_t data_properties,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_initialize()
 * Parameters:
 *      base_address [in] - The enclave base address as returned from the enclave_create API.
 *      info [in] - A pointer to the architecture-specific information to use to initialize the enclave.
 *      info_size [in] - The length of the structure that the info parameter points to, in bytes.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      non-zero - The function succeeds.
 *      zero - The function fails and the extended error information will be in the enclave_error parameter if used.
*/
bool COMM_API enclave_initialize(
    COMM_IN void* base_address,
    COMM_IN const void* info,
    COMM_IN size_t info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_delete()
 * Parameters:
 *      base_address [in] - The enclave base address as returned from the enclave_create API.
 *      enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 * Return Value:
 *      non-zero - The function succeeds.
 *      zero - The function fails and the extended error information will be in the enclave_error parameter if used.
*/
bool COMM_API enclave_delete(
    COMM_IN void* base_address,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_get_information()
 * Parameters:
 * base_address [in] - The enclave base address as returned from the enclave_create API.
 * info_type[in] - Identifies the type of information requested. initialized.
 * output_info[out] - Pointer to information returned by the API
 * output_info_size[in, out] - Size of the output_info buffer, in bytes.  If the API succeeds, then this will return the number of bytes returned in output_info.  If the API fails with, ENCLAVE_INVALID_SIZE, then this will return the required size
 * enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 */
bool COMM_API enclave_get_information(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_OUT void* output_info,
    COMM_IN_OUT size_t* output_info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_set_information
 * Parameters
 * base_address [in] - The enclave base address as returned from the enclave_create API.
 * info_type[in] - Identifies the type of information requested. not been initialized.
 * input_info[in] - Pointer to information provided to the API
 * input_info_size[in] - Size of the information, in bytes, provided in input_info from the API.
 * enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 */
bool COMM_API enclave_set_information(
    COMM_IN void* base_address,
    COMM_IN uint32_t info_type,
    COMM_IN void* input_info,
    COMM_IN size_t input_info_size,
    COMM_OUT_OPT uint32_t* enclave_error);

/* enclave_get_features()
 * Parameters:
 *      None
 * Return Value:
 *      Returns flags indicating enclave features which are supported on the platform.
 */
uint32_t COMM_API enclave_get_features();

/* enclave_alloc()
 * Call OS to reserve region for EAUG, immediately or on-demand.
 *
 * Parameters
 * targt_addr [in] - Desired page aligned start address.
 * target_size [in] - Size of the region in bytes of multiples of page size.
 * data_properties [in] - Page types to be allocated, must be one of these:
 *      - ENCLAVE_PAGE_REG: regular page type. This is the default if not specified.
 *      - ENCLAVE_PAGE_SS_FIRST: the first page in shadow stack.
 *      - ENCLAVE_PAGE_SS_REST: the rest page in shadow stack.
 * alloc_flags [in] - A bitwise OR of flags describing committing mode, committing
 *      order, address preference, page type. The untrusted side. Implementation
 *      should always invoke mmap syscall with MAP_SHARED|MAP_FIXED_NOREPLACE, and
 *      translate following additional bits to proper parameters invoking mmap or
 *      other SGX specific syscall(s) provided by the kernel. The alloc_flags param
 *      of this interface should include exactly one of following for committing mode:
 *      - ENCLAVE_EMA_COMMIT_NOW: reserves memory range with ENCLAVE_PAGE_READ|SGX_EMA_PROT_WRITE, if supported,
 *          kernel is given a hint to EAUG EPC pages for the area as soon as possible.
 *      - ENCLAVE_EMA_COMMIT_ON_DEMAND: reserves memory range, EPC pages can be EAUGed upon #PF.
 *        ORed with zero or one of the committing order flags:
 *          - ENCLAVE_EMA_GROWSDOWN: if supported, a hint given for the kernel to EAUG pages from higher
 *              to lower addresses, no gaps in addresses above the last committed.
 *          - ENCLAVE_EMA_GROWSUP: if supported, a hint given for the kernel to EAUG pages from lower
 *              to higher addresses, no gaps in addresses below the last committed.
 * enclave_error [out, optional] - An optional pointer to a variable that receives an enclave error code.
 *
 * Return Values:
 * ENCLAVE_ERROR_SUCCESS(0):    The operation was successful.
 * ENCLAVE_NOT_SUPPORTED:       Enavle feature is not supported by the system
 * ENCLAVE_LOST:                May be returned if the enclave has been removed or if it has not been initialized (via EINIT)
 * ENCLAVE_INVALID_ADDRESS:     The start address does not point to an enclave.
 * ENCLAVE_INVALID_PARAMETER:   An invalid combination of flags was provided.
 * ENCLAVE_OUT_OF_MEMORY:       No EPC left (some OSes like Linux), or system is out of memory for internal allocation by OS or this function.
 * ENCLAVE_DEVICE_NO_MEMORY:    NO EPC left (some OSes like Windows)
 * ENCLAVE_INVALID_ADDRESS:     Address does not point to an enclave or valid memory within the enclave
 * ENCLAVE_NOT_INITIALIZED:     May be returned if the enclave has not been initialized (via EINIT).
 *                              Some configurations may give ENCLAVE_LOST if the enclave has not been initialized.
 * ENCLAVE_UNEXPECTED:          Unexpected error.
 */

uint32_t COMM_API enclave_alloc (
    COMM_IN      void*     target_addr,
    COMM_IN      size_t    target_size,
    COMM_IN      uint32_t  data_properties,
    COMM_IN      uint32_t  alloc_flags,
    COMM_OUT_OPT uint32_t* enclave_error
);

/* enclave_modify()
 * Call OS to change permissions, type, or notify EACCEPT done after TRIM.
 *
 * Parameters:
 * target_addr [in] - Start address of the memory to change protections.
 * target_size [in] - Length of the area.  This must be a multiple of the page size.
 * from_data_properties [in] - The original EPCM flags of the EPC pages to be modified.
 *            Must be bitwise OR of following:
 *            ENCLAVE_PAGE_READ
 *            ENCLAVE_PAGE_WRITE
 *            ENCLAVE_PAGE_EXEC
 *            ENCLAVE_PAGE_REG: regular page, changeable to TRIM or TCS
 *            ENCLAVE_PAGE_TRIM: signal to the kernel EACCEPT is done for TRIM pages.
 * to_data_properties [in] - The target EPCM flags. This must be bitwise OR of following:
 *            ENCLAVE_PAGE_READ
 *            ENCLAVE_PAGE_WRITE
 *            ENCLAVE_PAGE_EXEC
 *            ENCLAVE_PAGE_TRIM: change the page type to PT_TRIM. Note the address
 *                      range for trimmed pages may still be reserved by enclave with
 *                      proper permissions.
 *            ENCLAVE_PAGE_TCS: change the page type to PT_TCS
 *
 * Return Values:
 * ENCLAVE_ERROR_SUCCESS(0):    The operation was successful.
 * ENCLAVE_NOT_SUPPORTED:       Enclave feature is not supported by the system
 * ENCLAVE_LOST:                May be returned if the enclave has been removed or if it has not been initialized (via EINIT)
 * ENCLAVE_INVALID_PARAMETER:   An invalid combination of flags was provided.
 * ENCLAVE_OUT_OF_MEMORY:       No EPC left (some OSes like Linux), or system is out of memory for internal allocation by OS or this function.
 * ENCLAVE_DEVICE_NO_MEMORY:    NO EPC left (some OSes like Windows)
 * ENCLAVE_INVALID_ADDRESS:     Address does not point to an enclave or valid memory within the enclave
 * ENCLAVE_NOT_INITIALIZED:     May be returned if the enclave has not been initialized (via EINIT).
 *                              Some configurations may give ENCLAVE_LOST if the enclave has not been initialized.
 * ENCLAVE_UNEXPECTED:          Unexpected error.
 */

uint32_t COMM_API enclave_modify (
    COMM_IN      void*     target_addr,
    COMM_IN      size_t    target_size,
    COMM_IN      uint32_t  from_data_properties,
    COMM_IN      uint32_t  to_data_properties,
    COMM_OUT_OPT uint32_t* enclave_error
);

/**
 * The enclave features flags describe additional enclave features
 * which are supported by the platform.  A value of 0 indicates not features are supported.
 */
typedef enum {
    ENCLAVE_FEATURE_NONE = 0,
    ENCLAVE_FEATURE_SGX1 = 0x00000001, /* The platform (HW and OS) supports SGX1 */
    ENCLAVE_FEATURE_SGX2 = 0x00000002, /* The platform (HW and OS) supports SGX2 */
}enclave_features_t;

#ifdef __cplusplus
}
#endif

#endif
