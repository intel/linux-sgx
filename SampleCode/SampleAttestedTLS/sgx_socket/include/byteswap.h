#ifndef _BYTESWAP_H
#define _BYTESWAP_H

#include <features.h>
#include <stdint.h>

static __inline uint16_t __bswap_16(uint16_t __x)
{
	return (uint16_t)((__x<<8) | (__x>>8));
}

static __inline uint32_t __bswap_32(uint32_t __x)
{
	return (__x>>24) | (__x>>8&0xff00) | (__x<<8&0xff0000) | (__x<<24);
}

#define bswap_16(x) __bswap_16(x)
#define bswap_32(x) __bswap_32(x)

#endif
