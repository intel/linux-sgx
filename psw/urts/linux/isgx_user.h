/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation.
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
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 */

#ifndef _UAPI_ASM_X86_SGX_H
#define _UAPI_ASM_X86_SGX_H


#include <linux/types.h>
#include <linux/ioctl.h>

#define SGX_MAGIC 0xA4

/**
 * enum sgx_epage_flags - page control flags
 * %SGX_PAGE_MEASURE:	Measure the page contents with a sequence of
 *			ENCLS[EEXTEND] operations.
 */
enum sgx_page_flags {
	SGX_PAGE_MEASURE	= 0x01,
};


/**
 * Driver Type Definitions
 *   SGX_DRIVER_UNKNOWN     0x0   - uninitialized
 *   SGX_DRIVER_IN_KERNEL   0x1   - in-kernel driver: supports the new IOCTL interface
 *              /dev/sgx/enclave  - for enclave loading IOCTLs using the filehandle
 *                                     requires SGX_IOC_ENCLAVE_SET_ATTRIBUTE to get access to provision key
 *              /dev/sgx/provision- for provision key configuration
 *   SGX_DRIVER_OUT_OF_TREE 0x2   - out-of-tree driver which uses legacy launch and supports EDMM
 *              /dev/isgx         - for enclave loading IOCTLs
 *   SGX_DRIVER_DCAP        0x3   - DCAP driver which partially supports in-kernel interface in that it:
 *                                1) Does not take a launch token for init - uses SGX_IOC_ENCLAVE_INIT_IN_KERNEL
 *                                2) Takes SGX_IOC_ENCLAVE_SET_ATTRIBUTE, but also whitelists a specific signing key
 *                                Eventually, this driver will switch to support the same interface as SGX_DRIVER_IN_KERNEL
 *              /dev/sgx          - for enclave loading IOCTLs
 *              /dev/??           - for provision key configuration
 */
#define SGX_DRIVER_UNKNOWN      0x0
#define SGX_DRIVER_IN_KERNEL    0x1
#define SGX_DRIVER_OUT_OF_TREE  0x2
#define SGX_DRIVER_DCAP         0x3




#define SGX_IOC_ENCLAVE_CREATE \
	_IOW(SGX_MAGIC, 0x00, struct sgx_enclave_create)
#define SGX_IOC_ENCLAVE_ADD_PAGE \
	_IOW(SGX_MAGIC, 0x01, struct sgx_enclave_add_page)
#define SGX_IOC_ENCLAVE_INIT \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init)
#define SGX_IOC_ENCLAVE_SET_ATTRIBUTE \
	_IOW(SGX_MAGIC, 0x03, struct sgx_enclave_set_attribute)
#define SGX_IOC_ENCLAVE_EMODPR \
	_IOW(SGX_MAGIC, 0x09, struct sgx_modification_param)
#define SGX_IOC_ENCLAVE_MKTCS \
	_IOW(SGX_MAGIC, 0x0a, struct sgx_range)
#define SGX_IOC_ENCLAVE_TRIM \
	_IOW(SGX_MAGIC, 0x0b, struct sgx_range)
#define SGX_IOC_ENCLAVE_NOTIFY_ACCEPT \
	_IOW(SGX_MAGIC, 0x0c, struct sgx_range)
#define SGX_IOC_ENCLAVE_PAGE_REMOVE \
	_IOW(SGX_MAGIC, 0x0d, unsigned long)

//Note: SGX_IOC_ENCLAVE_CREATE is the same for in-kernel except that it returns a file handle for in-kernel
#define SGX_IOC_ENCLAVE_ADD_PAGES_V36 \
	_IOWR(SGX_MAGIC, 0x01, struct sgx_enclave_add_pages_v36)
#define SGX_IOC_ENCLAVE_ADD_PAGES_IN_KERNEL \
	_IOWR(SGX_MAGIC, 0x01, struct sgx_enclave_add_pages_in_kernel)
#define SGX_IOC_ENCLAVE_INIT_IN_KERNEL \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init_in_kernel)
#define SGX_IOC_ENCLAVE_SET_ATTRIBUTE_IN_KERNEL \
	_IOW(SGX_MAGIC, 0x03, struct sgx_enclave_set_attribute_in_kernel)



#define SGX_IOC_ENCLAVE_INIT_DCAP \
	_IOW(SGX_MAGIC, 0x02, struct sgx_enclave_init_dcap)


/* SGX leaf instruction return values */
#define SGX_INVALID_SIG_STRUCT		1
#define SGX_INVALID_ATTRIBUTE		2
#define SGX_BLKSTATE			3
#define SGX_INVALID_MEASUREMENT		4
#define SGX_NOTBLOCKABLE		5
#define SGX_PG_INVLD			6
#define SGX_LOCKFAIL			7
#define SGX_INVALID_SIGNATURE		8
#define SGX_MAC_COMPARE_FAIL		9
#define SGX_PAGE_NOT_BLOCKED		10
#define SGX_NOT_TRACKED			11
#define SGX_VA_SLOT_OCCUPIED		12
#define SGX_CHILD_PRESENT		13
#define SGX_ENCLAVE_ACT			14
#define SGX_ENTRYEPOCH_LOCKED		15
#define SGX_INVALID_LICENSE		16
#define SGX_PREV_TRK_INCMPL		17
#define SGX_PG_IS_SECS			18
#define SGX_PAGE_NOT_MODIFIABLE		20
#define SGX_INVALID_CPUSVN		32
#define SGX_INVALID_ISVSVN		64
#define SGX_UNMASKED_EVENT		128
#define SGX_INVALID_KEYNAME		256

/* IOCTL return values */
#define SGX_POWER_LOST_ENCLAVE	0x40000000
#define SGX_LE_ROLLBACK			0x40000001
#define SGX_INVALID_PRIVILEGE   0x40000002
#define SGX_UNEXPECTED_ERROR    0x40000003

/**
 * struct sgx_enclave_create - parameter structure for the
 *                             %SGX_IOC_ENCLAVE_CREATE ioctl
 * @src:	address for the SECS page data
 */
struct sgx_enclave_create  {
	__u64	src;
} __attribute__((packed));

/**
 * struct sgx_enclave_add_page - parameter structure for the
 *                               %SGX_IOC_ENCLAVE_ADD_PAGE ioctl
 * @addr:	address within the ELRANGE
 * @src:	address for the page data
 * @secinfo:	address for the SECINFO data
 * @mrmask:	bitmask for the measured 256 byte chunks
 * @reserved:	reserved for future use
 */
struct sgx_enclave_add_page {
	__u64	addr;
	__u64	src;
	__u64	secinfo;
	__u16	mrmask;
} __attribute__((packed));

/**
 * Kernel patch v36 or earlier, and DCAP driver 1.36 or earlier
 * struct sgx_enclave_add_pages_v36 - parameter structure for the
 *                                %SGX_IOC_ENCLAVE_ADD_PAGE ioctl
 * @src:        start address for the page data
 * @offset:     starting page offset
 * @length:     length of the data (multiple of the page size)
 * @secinfo:address for the SECINFO data
 * @flags:      page control flags
 * @count:      number of bytes added (multiple of the page size)
 */

struct sgx_enclave_add_pages_v36 {
        __u64   src;
        __u64   offset;
        __u64   length;
        __u64   secinfo;
        __u64   flags;
        __u64   count;
} __attribute__((packed));


/**
 * struct sgx_enclave_add_pages_in_kernel - parameter structure for the
 *                                %SGX_IOC_ENCLAVE_ADD_PAGE ioctl
 * @src:	start address for the page data
 * @offset:	starting page offset
 * @length:	length of the data (multiple of the page size)
 * @secinfo:address for the SECINFO data
 * @flags:	page control flags
 */
struct sgx_enclave_add_pages_in_kernel {
	__u64	src;
	__u64	offset;
	__u64	length;
	__u64	secinfo;
	__u64	flags;
} __attribute__((packed));

/**
 * struct sgx_enclave_init - parameter structure for the
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @addr:	address in the ELRANGE
 * @sigstruct:	address for the page data
 * @einittoken:	address for the SECINFO data
 */
struct sgx_enclave_init {
	__u64	addr;
	__u64	sigstruct;
	__u64	einittoken;
} __attribute__((packed));

/**
 * struct sgx_enclave_init_in_kernel - parameter structure for the dcap
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @addr:	address in the ELRANGE
 * @sigstruct:	address for SIGSTRUCT data
 */
struct sgx_enclave_init_dcap {
	__u64	addr;
	__u64	sigstruct;
};


/**
 * struct sgx_enclave_init_in_kernel - parameter structure for the in-kernel
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @sigstruct:	address for SIGSTRUCT data
 */

struct sgx_enclave_init_in_kernel {
	__u64	sigstruct;
};


/**
 * struct sgx_enclave_set_attribute - parameter structure for the
 *                                    %SGX_IOC_ENCLAVE_SET_ATTRIBUTE ioctl
 * @addr:               address within the ELRANGE
 * @attribute_fd:       file handle of the attribute file in the securityfs
 */
struct sgx_enclave_set_attribute {
    __u64   addr;
    __u64   attribute_fd;
};


struct sgx_enclave_set_attribute_in_kernel {
    __u64   attribute_fd;
};


struct sgx_enclave_destroy {
	__u64	addr;
} __attribute__((packed));


/*
 *     SGX2.0 definitions
 */

#define SGX_GROW_UP_FLAG	1
#define SGX_GROW_DOWN_FLAG	2

struct sgx_range {
	unsigned long start_addr;
	unsigned int nr_pages;
};

struct sgx_modification_param {
	struct sgx_range range;
	unsigned long flags;
};

#endif /* _UAPI_ASM_X86_SGX_H */
