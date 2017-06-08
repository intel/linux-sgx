/**
*   Copyright(C) 2011-2017 Intel Corporation All Rights Reserved.
*
*   The source code, information  and  material ("Material") contained herein is
*   owned  by Intel Corporation or its suppliers or licensors, and title to such
*   Material remains  with Intel Corporation  or its suppliers or licensors. The
*   Material  contains proprietary information  of  Intel or  its  suppliers and
*   licensors. The  Material is protected by worldwide copyright laws and treaty
*   provisions. No  part  of  the  Material  may  be  used,  copied, reproduced,
*   modified, published, uploaded, posted, transmitted, distributed or disclosed
*   in any way  without Intel's  prior  express written  permission. No  license
*   under  any patent, copyright  or  other intellectual property rights  in the
*   Material  is  granted  to  or  conferred  upon  you,  either  expressly,  by
*   implication, inducement,  estoppel or  otherwise.  Any  license  under  such
*   intellectual  property  rights must  be express  and  approved  by  Intel in
*   writing.
*
*   *Third Party trademarks are the property of their respective owners.
*
*   Unless otherwise  agreed  by Intel  in writing, you may not remove  or alter
*   this  notice or  any other notice embedded  in Materials by Intel or Intel's
*   suppliers or licensors in any way.
*/

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sgx_uae_service.h>
#include <sgx_capable.h>

/* __cpuid(unsinged int info[4], unsigned int leaf, unsigned int subleaf); */
/* Because gcc's __get_cpuid() intrinsic is difficult to work with */
#define __cpuid(x,y,z) asm volatile("cpuid":"=a"(x[0]),"=b"(x[1]),"=c"(x[2]),"=d"(x[3]):"a"(y),"c"(z))

#define EFIFS_PATH		"/sys/firmware/efi/"
#define EFIVARS_PATH 	EFIFS_PATH"efivars/"
#define EFIVAR_EPCBIOS	EFIVARS_PATH"EPCBIOS-c60aa7f6-e8d6-4956-8ba1-fe26298f5e87"
#define EFIVAR_EPCSW	EFIVARS_PATH"EPCSW-d69a279b-58eb-45d1-a148-771bb9eb5251"

static int _is_sgx_available();
static int _is_cpu_supported();

sgx_status_t sgx_is_capable (int *sgx_capable)
{
	struct stat sb;

	if ( sgx_capable == NULL ) return SGX_ERROR_INVALID_PARAMETER;

	if ( ! _is_cpu_supported() ) {
		*sgx_capable= 0;
		return SGX_SUCCESS;
	}

	if ( _is_sgx_available() ) {
		*sgx_capable= 1;
		return SGX_SUCCESS;
	}

	/* Check to see if the Software Control Interface is available */

	if ( stat(EFIVAR_EPCBIOS, &sb) == -1 ) {
		if ( errno == EACCES ) return SGX_ERROR_NO_PRIVILEGE;
		*sgx_capable = 0;
		return SGX_SUCCESS;
	}

	*sgx_capable= 1;
	return SGX_SUCCESS;
}

sgx_status_t sgx_cap_get_status (sgx_device_status_t *sgx_device_status)
{
	struct stat sb;
	int has_efifs= 0;

	if ( sgx_device_status == NULL ) return SGX_ERROR_INVALID_PARAMETER;

	if ( ! _is_cpu_supported() ) {
		*sgx_device_status= SGX_DISABLED_UNSUPPORTED_CPU;
		return SGX_SUCCESS;
	}

	if ( _is_sgx_available() ) {
		*sgx_device_status= SGX_ENABLED;
		return SGX_SUCCESS;
	}

	/*
	 * Intel SGX is supported, but not enabled. Figure out what
	 * it will take to enable it.
	 */

	/* Were we booted in UEFI mode? */

	if ( stat(EFIFS_PATH, &sb) == 0 ) {
		has_efifs= 1;

		if ( stat(EFIVARS_PATH, &sb) == -1 )
		{
			/* We have /sys/firmware/efi but not efivars */

			switch (errno) {
			case EACCES:
				return SGX_ERROR_NO_PRIVILEGE;
			case ENOENT:
			case ENOTDIR:
				break;
			default:
				return SGX_ERROR_UNEXPECTED;
			}
		}
	} else {
		switch (errno) {
		case EACCES:
			return SGX_ERROR_NO_PRIVILEGE;
		case ENOENT:
		case ENOTDIR:
			break;
		default:
			return SGX_ERROR_UNEXPECTED;
		}
	} 

	if ( ! has_efifs ) {
		/*
		 * We don't have /sys/firmware/efi mounted. It could have been
		 * unmounted by the user, or we might not have UEFI support in
		 * the OS. If /boot/efi exists, then we are probably capable of
		 * UEFI and should report SGX_DISABLED. Otherwise report
		 * SGX_DISABLED_LEGACY_OS.
		 */

		if ( stat("/boot/efi", &sb) == 0 ) *sgx_device_status= SGX_DISABLED;
		else {
			switch(errno) {
			case ENOENT:
			case ENOTDIR:
				*sgx_device_status= SGX_DISABLED_LEGACY_OS;
				break;
			default:
				/* 
				 * We don't have enough information to figure this out
				 * so report SGX_DISABLED.
				 */
				*sgx_device_status= SGX_DISABLED;
			}

		} 

		return SGX_SUCCESS;
	}

	/*
	 * We have access to efivars. Now examine the EFI variable for the
	 * Software Control Interface.
	 */

	if ( stat(EFIVAR_EPCBIOS, &sb) == -1 ) {
		if ( errno == EACCES ) return SGX_ERROR_NO_PRIVILEGE;

		/* No SCI is present so we can't do a s/w enabled */

		*sgx_device_status= SGX_DISABLED_MANUAL_ENABLE;
		return SGX_SUCCESS;
	}

	/*
	 * Check to see if the software enable has already been
	 * performed. If so, then we will be enabled on the next
	 * reboot.
	 */

	if ( stat(EFIVAR_EPCSW, &sb) == -1 ) {
		if ( errno == EACCES ) return SGX_ERROR_NO_PRIVILEGE;

		/* The software enable hasn't been attempted yet. */

		*sgx_device_status= SGX_DISABLED_SCI_AVAILABLE;
		return SGX_SUCCESS;
	}

	/* Software enable has occurred. Need a reboot. */

	*sgx_device_status= SGX_DISABLED_REBOOT_REQUIRED;

	return SGX_SUCCESS;
}

/* Determine if the CPU supports Intel SGX */

static int _is_cpu_supported()
{
	unsigned int info[4];
	unsigned int *ebx, *ecx, *edx;

	ebx= &info[1];
	ecx= &info[2];
	edx= &info[3];

	/* Is this an Intel CPU? */

	__cpuid (info, 0x00, 0);
	if ( *ebx != 0x756e6547 || *ecx != 0x6c65746e || *edx != 0x49656e69 )
		return 0;

	/* Does the CPU support Intel SGX? */

	__cpuid (info, 0x07, 0);

	return ( *ebx & (0x1<<2) );
}

/* Are SGX instructions available for use? */

static int _is_sgx_available ()
{
	unsigned int info[4];
	unsigned int *eax, *ebx, *ecx, *edx;
	unsigned int subleaf= 2;
	unsigned int flag;

	eax= &info[0];
	ebx= &info[1];
	ecx= &info[2];
	edx= &info[3];

	/* Are Intel SGX instructions available for use? */

	__cpuid(info, 0x12, 0);

	flag= *eax&0x3;
	if ( flag == 0 ) return 0;

	/* Do we have non-zero, max enclave sizes? */

	if ( (*edx & 0xFFFF) == 0 ) return 0;

	/*
	 * Enumerate the subleafs for the EPC. At least one must be a valid
	 * subleaf that describes a page. 
	 */

	while (1) {
		__cpuid(info, 0x12, subleaf);

		/* 
		 * Is this an invalid subleaf? If we've hit an invalid subleaf
		 * before finding a valid subleaf with a non-zero page size,
		 * then we have no EPC memory allocated, and thus no Intel SGX
		 * capability.
		 */

		if ( ! (*eax & 0x1) ) return 0;

		/*
		 * Is there a non-zero size for this EPC subleaf? If so, we
		 * have memory allocated to the EPC for Intel SGX, and are
		 * enabled.
		 */

		if (
			(*eax&0xFFFFF000 || *ebx&0xFFFFF) &&
			(*ecx&0xFFFFF000 || *edx&0xFFFFF)
		) return 1;

		++subleaf;
	}

	/* We'll never get here, but we need to keep the compiler happy */

	return 0;
}

sgx_status_t sgx_cap_enable_device (sgx_device_status_t *sgx_device_status)
{
	sgx_status_t status;
	struct epcbios_stuct {
		uint32_t attrs;
		uint32_t sprmbins;
		uint32_t maxepcsz;
		/* There's more, but this is all we need */
	} epcbios;
	struct epcsw_struct {
		uint32_t attrs;
		uint32_t maxepcsz;
	} epcsw;
	FILE *fefivar;

	if ( sgx_device_status == NULL ) return SGX_ERROR_INVALID_PARAMETER;

	status= sgx_cap_get_status(sgx_device_status);
	if ( status != SGX_SUCCESS ) return status;

	/*
	 * If we get back anything other than SGX_DISABLED_SCI_AVAILABLE
	 * then return, because there is nothing to do.
	 */

	if ( *sgx_device_status != SGX_DISABLED_SCI_AVAILABLE )
		return SGX_SUCCESS;

	/* Attempt the software enable */

	/* First, read the EPCBIOS EFI variable to get the max EPC size */

	fefivar= fopen(EFIVAR_EPCBIOS, "r");
	if ( fefivar == NULL ) {
		if ( errno == EACCES ) return SGX_ERROR_NO_PRIVILEGE;

		return SGX_ERROR_UNEXPECTED;
	}

	/*
	 * The first 4 bytes are the EFI variable attributes. Data starts
	 * at offset 0x4, and the value we want is a UINT32 at offset 0x8.
	 */

	if ( fread(&epcbios, sizeof(epcbios), 1, fefivar) != 1 ) {
		fclose(fefivar);
		return SGX_ERROR_UNEXPECTED;
	}

	fclose(fefivar);

	/*
	 * Now create the EPCSW EFI variable. The variable data is a 
	 * single UINT32 specifying the requested EPC size.
	 */

	epcsw.attrs= epcbios.attrs;
	epcsw.maxepcsz= epcbios.maxepcsz;

	fefivar= fopen(EFIVAR_EPCSW, "w");
	if ( fefivar == NULL ) {
		if ( errno == EACCES ) return SGX_ERROR_NO_PRIVILEGE;

		return SGX_ERROR_UNEXPECTED;
	}

	/* Write out the EPCSW structure */

	if ( fwrite(&epcsw, sizeof(epcsw), 1, fefivar) != 1 ) {
		unlink(EFIVAR_EPCSW);
		fclose(fefivar);
		return SGX_ERROR_UNEXPECTED;
	}

	fclose(fefivar);

	*sgx_device_status= SGX_DISABLED_REBOOT_REQUIRED;

	return SGX_SUCCESS;
}
