/**
 * @file dis_main.c
 * @author Xiang Cheng (xiang.cheng@intel.com)
 * @brief
 * @version 0.1
 * @date 2022-06-10
 *
 * @copyright Copyright (c) 2022
 *
 * I think the minimum CPU flag we need is AVX2
 *
 */
#include <immintrin.h>
#include "ctd.h"
#include<string.h>
#define DUDECT_IMPLEMENTATION
#include "dudect.h"
#define NUM_MM_REGS 16



#ifndef SAMPLES
#define SAMPLES         100000

#endif






typedef long long __m128i __attribute__((__vector_size__(16), __may_alias__));
typedef long long __m256i __attribute__((__vector_size__(32), __may_alias__));
typedef long long __m512i __attribute__ ((__vector_size__ (64), __may_alias__));
typedef long long __v2di __attribute__((__vector_size__(16)));
typedef char __v16qi __attribute__((__vector_size__(16)));
typedef int __v4si __attribute__((__vector_size__(16)));
typedef long long __v2di __attribute__((__vector_size__(16)));
typedef unsigned long long __v2du __attribute__((__vector_size__(16)));
typedef long long __m128i_u __attribute__((__vector_size__(16), __may_alias__, __aligned__(1)));
typedef long long __v4di __attribute__((__vector_size__(32)));
typedef char __v32qi __attribute__((__vector_size__(32)));
typedef unsigned long long __v4du __attribute__((__vector_size__(32)));
typedef int __v8si __attribute__((__vector_size__(32)));

/**
 * @brief Lookup table for all prefixes and opcode 1
 * Each entry is 1 byte, 8 bits:
 *    _ _ _ _ _ _ _ _
 *    1 2 3 4 5 6 7 8
 *     a   b   c   d
 * Each 2 bits are for one unit, we call it a/b/c/d
 * Switch (a) =>
 *        case "0": means a standard prefix, there are 4 groups(refer to IA-32 manual Sec 2.1.1.1)
 *                  then b is it's group number and cd together means its sequence in the group, starting 0
 *                  e.g. prefix 0x64 is the 5th prefix in group 2 => 0b00010100 0x14
 *        case "1": means a rex prefix, other fields are unused
 *        case "2": means a standard opcode, b is set 1 for normal opcode
 *                  c means accessing mod:
 *                      switch (c) =>
 *                          case "0": no explict memory access
 *                          case "1": memory read
 *                          case "2": memory write, here we assume write includes read access
 *                          case "3": reserved, illegal
 *                  d means accessing size: in standard instruction, we only have: byte, word(2 bytes), dword/fword(double word, 4 bytes), qword(quadratic word, 8 bytes)
 *                      switch (d) =>
 *                          case "0": byte
 *                          case "1": word
 *                          case "2": dword/fword
 *                          case "3": qword
 *                  b = 2: string related instructions: https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/9
 *                      There are 5 sets of instructions(6c/6d/6e/6f/aa/ab/ac/ad/ae/af), both accessing either [RDI] or [RSI].
 *                      c: means the register to access:
 *                          0 => RSI
 *                          1 => RDI
 *                          (in our ctx, rdi is later than rsi by 1, so we use this encoding and base offset to direct get value)
 *                      d: means accessing mod:
 *                          0 => read
 *                          1 => write
 *                  b = 3: stack instructions: call/push: https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/14
 *                      all these instructions will access [RSP] with WRITE
 *
 *        case "3": extended map for 1 opcode, refer to Section 2 A.4
 *                  b means different rows:
 *                      switch (b) =>
 *                          case "0": row opcode 80 - 83, 8f
 *                          case "1": row opcode c0/c1/d0/d1/d2/d3
 *                          case "2": row F6/F7
 *                          case "3": row fe/ff/c6/c7
 *                  c is either 01B or 10B, since the r/w will depend on one more table lookup
 *                  d is for access size
 *                      switch (d) =>
 *                          case "0": byte
 *                          case "1": word
 *                          case "2": dword/fword
 *                          case "3": qword
 *
 *
 * Notes:
 *  1. The escape opcode 0xf is regraded as normal, no memory access
 *  2. Unused parts are set to 0
 */
static uint8_t standard[256] = {
        0x98, // 0x0
        0x9a, // 0x1
        0x94, // 0x2
        0x96, // 0x3
        0x90, // 0x4
        0x90, // 0x5
        0x90, // 0x6
        0x90, // 0x7
        0x98, // 0x8
        0x9a, // 0x9
        0x94, // 0xa
        0x96, // 0xb
        0x90, // 0xc
        0x90, // 0xd
        0x90, // 0xe
        0x80, // 0xf
        0x98, // 0x10
        0x9a, // 0x11
        0x94, // 0x12
        0x96, // 0x13
        0x90, // 0x14
        0x90, // 0x15
        0x90, // 0x16
        0x90, // 0x17
        0x98, // 0x18
        0x9a, // 0x19
        0x94, // 0x1a
        0x96, // 0x1b
        0x90, // 0x1c
        0x90, // 0x1d
        0x90, // 0x1e
        0x90, // 0x1f
        0x98, // 0x20
        0x9a, // 0x21
        0x94, // 0x22
        0x96, // 0x23
        0x90, // 0x24
        0x90, // 0x25
        0x13, // 0x26
        0x90, // 0x27
        0x98, // 0x28
        0x9a, // 0x29
        0x94, // 0x2a
        0x96, // 0x2b
        0x90, // 0x2c
        0x90, // 0x2d
        0x10, // 0x2e
        0x90, // 0x2f
        0x98, // 0x30
        0x9a, // 0x31
        0x94, // 0x32
        0x96, // 0x33
        0x90, // 0x34
        0x90, // 0x35
        0x11, // 0x36
        0x90, // 0x37
        0x94, // 0x38
        0x96, // 0x39
        0x94, // 0x3a
        0x96, // 0x3b
        0x90, // 0x3c
        0x90, // 0x3d
        0x12, // 0x3e
        0x90, // 0x3f
        0x40, // 0x40
        0x40, // 0x41
        0x40, // 0x42
        0x40, // 0x43
        0x40, // 0x44
        0x40, // 0x45
        0x40, // 0x46
        0x40, // 0x47
        0x40, // 0x48
        0x40, // 0x49
        0x40, // 0x4a
        0x40, // 0x4b
        0x40, // 0x4c
        0x40, // 0x4d
        0x40, // 0x4e
        0x40, // 0x4f
        0xb0, // 0x50
        0xb0, // 0x51
        0xb0, // 0x52
        0xb0, // 0x53
        0xb0, // 0x54
        0xb0, // 0x55
        0xb0, // 0x56
        0xb0, // 0x57
        0x90, // 0x58
        0x90, // 0x59
        0x90, // 0x5a
        0x90, // 0x5b
        0x90, // 0x5c
        0x90, // 0x5d
        0x90, // 0x5e
        0x90, // 0x5f
        0xb0, // 0x60
        0x90, // 0x61
        0x90, // 0x62
        0x95, // 0x63
        0x14, // 0x64
        0x15, // 0x65
        0x20, // 0x66
        0x30, // 0x67
        0xb0, // 0x68
        0x96, // 0x69
        0xb0, // 0x6a
        0x96, // 0x6b
        0xa5, // 0x6c
        0xa5, // 0x6d
        0xa0, // 0x6e
        0xa0, // 0x6f
        0x90, // 0x70
        0x90, // 0x71
        0x90, // 0x72
        0x90, // 0x73
        0x90, // 0x74
        0x90, // 0x75
        0x90, // 0x76
        0x90, // 0x77
        0x90, // 0x78
        0x90, // 0x79
        0x90, // 0x7a
        0x90, // 0x7b
        0x90, // 0x7c
        0x90, // 0x7d
        0x90, // 0x7e
        0x90, // 0x7f
        0xc4, // 0x80
        0xc6, // 0x81
        0xc4, // 0x82
        0xc6, // 0x83
        0x94, // 0x84
        0x96, // 0x85
        0x94, // 0x86
        0x96, // 0x87
        0x98, // 0x88
        0x9a, // 0x89
        0x94, // 0x8a
        0x96, // 0x8b
        0x99, // 0x8c
        0x90, // 0x8d
        0x95, // 0x8e
        0x9a, // 0x8f
        0x90, // 0x90
        0x90, // 0x91
        0x90, // 0x92
        0x90, // 0x93
        0x90, // 0x94
        0x90, // 0x95
        0x90, // 0x96
        0x90, // 0x97
        0x90, // 0x98
        0x90, // 0x99
        0xb0, // 0x9a
        0x90, // 0x9b
        0xb0, // 0x9c
        0x90, // 0x9d
        0x90, // 0x9e
        0x90, // 0x9f
        0x90, // 0xa0
        0x90, // 0xa1
        0x90, // 0xa2
        0x90, // 0xa3
        0xa5, // 0xa4
        0xa5, // 0xa5
        0xa0, // 0xa6
        0xa0, // 0xa7
        0x90, // 0xa8
        0x90, // 0xa9
        0xa5, // 0xaa
        0xa5, // 0xab
        0xa0, // 0xac
        0xa0, // 0xad
        0xa4, // 0xae
        0xa4, // 0xaf
        0x90, // 0xb0
        0x90, // 0xb1
        0x90, // 0xb2
        0x90, // 0xb3
        0x90, // 0xb4
        0x90, // 0xb5
        0x90, // 0xb6
        0x90, // 0xb7
        0x90, // 0xb8
        0x90, // 0xb9
        0x90, // 0xba
        0x90, // 0xbb
        0x90, // 0xbc
        0x90, // 0xbd
        0x90, // 0xbe
        0x90, // 0xbf
        0xd8, // 0xc0
        0xda, // 0xc1
        0x90, // 0xc2
        0x90, // 0xc3
        0x90, // 0xc4
        0x90, // 0xc5
        0xf8, // 0xc6
        0xfa, // 0xc7
        0x90, // 0xc8
        0x90, // 0xc9
        0x90, // 0xca
        0x90, // 0xcb
        0x90, // 0xcc
        0x90, // 0xcd
        0x90, // 0xce
        0x90, // 0xcf
        0xd8, // 0xd0
        0xda, // 0xd1
        0xd8, // 0xd2
        0xda, // 0xd3
        0x90, // 0xd4
        0x90, // 0xd5
        0x90, // 0xd6
        0x90, // 0xd7
        0x90, // 0xd8
        0x90, // 0xd9
        0x90, // 0xda
        0x90, // 0xdb
        0x90, // 0xdc
        0x90, // 0xdd
        0x90, // 0xde
        0x90, // 0xdf
        0x90, // 0xe0
        0x90, // 0xe1
        0x90, // 0xe2
        0x90, // 0xe3
        0x90, // 0xe4
        0x90, // 0xe5
        0x90, // 0xe6
        0x90, // 0xe7
        0xb0, // 0xe8
        0x90, // 0xe9
        0x90, // 0xea
        0x90, // 0xeb
        0x90, // 0xec
        0x90, // 0xed
        0x90, // 0xee
        0x90, // 0xef
        0x03, // 0xf0
        0x90, // 0xf1
        0x01, // 0xf2
        0x02, // 0xf3
        0x90, // 0xf4
        0x90, // 0xf5
        0xe4, // 0xf6
        0xe6, // 0xf7
        0x90, // 0xf8
        0x90, // 0xf9
        0x90, // 0xfa
        0x90, // 0xfb
        0x90, // 0xfc
        0x90, // 0xfd
        0xf8, // 0xfe
        0xf6, // 0xff
};

/**
 * @brief Lookup table for opcode 2
 * this table is different from `standard` table, since we now know all the elements are opcodes, no more prefixes
 * also the memory access size increased
 * Each entry is 1 byte, 8 bits:
 *    _ _ _ _ _ _ _ _
 *    1 2 3 4 5 6 7 8
 *     a   b     c
 * We have a, b as similiar position as `standard` table, and the final c takes lower 4 bits
 * a is demote whether this is a valid opcode or escape opcode(since we are not going to support 3 opcode instructions)
 * switch (a):
 *      case "0": escape opcode, 0x38 or 0x3A, refer to IA-32 manual A.2.4.3
 *      case "2": a valid opcode. b is used for memory access, and c is the access size
 *              b has 3 states: no explicit access, read, write
 *              switch (b) =>
 *                  case "0": no memory access
 *                  case "1": memory read
 *                  case "2": memory write(here we assume write includes read permission)
 *                  case "3": unused
 *              c has 5 states: byte, word(2 bytes), dword/fword(double word, 4 bytes), qword(quadratic word, 8 bytes), xmmword(todo: we will figure it out)
 *              switch (c) =>
 *                  case "0": byte
 *                  case "1": word
 *                  case "2": dword/fword
 *                  case "3": qword
 *                  case "4": xmmword
 *      case "1": a valid normal opcode, but b needs further lookup for the normal table
 *              currently we have 0x7E, 0x1A, 0x1B for this case, because their mod will be changed by prefix, others no matter what prefix is, the mod is the same
 *              b will be a index meaning the b-th table to lookup in the 2 byte opcode normal lookup table
 *              b = switch (opcode 2) => {
 *                  case "0x7e" => 0
 *                  case "0x1a" => 1
 *                  case "0x1b" => 2
 *              }
 *              c will be the size as above
 *      case "3": a valid opcode with extension mode, refer toi Table A-3 in Vol 2
 *              here we borrow the highest bit from c to b, so we will have b with 3bits and c with 3 bits
 *              b is used as index in the table to lookup
 *              switch (b) =>
 *                  case "0" => 0x00
 *                  case "1" => 0xba
 *                  case "2" => 0xc7
 *                  case "3" => 0x01
 *                  case "4" => 0xae
 *                  case "5" => 0x18
 *
 * Note:
 *  1. Unused parts are set to 0
 *
 */
static uint8_t extended[256] = {
        0xc1, // 0x0 __
        0xd8, // 0x1
        0x90, // 0x2
        0x90, // 0x3
        0x80, // 0x4
        0x80, // 0x5
        0x80, // 0x6
        0x80, // 0x7
        0x80, // 0x8
        0x80, // 0x9
        0x80, // 0xa
        0x80, // 0xb
        0x80, // 0xc
        0x90, // 0xd
        0x80, // 0xe
        0x93, // 0xf
        0x94, // 0x10
        0xa4, // 0x11
        0x93, // 0x12
        0xa3, // 0x13
        0x94, // 0x14
        0x94, // 0x15
        0x93, // 0x16
        0xa3, // 0x17
        0xe8, // 0x18
        0x82, // 0x19
        0x54, // 0x1a
        0x64, // 0x1b
        0x82, // 0x1c
        0x82, // 0x1d
        0x82, // 0x1e
        0x82, // 0x1f
        0x80, // 0x20
        0x80, // 0x21
        0x80, // 0x22
        0x80, // 0x23
        0x80, // 0x24
        0x80, // 0x25
        0x80, // 0x26
        0x80, // 0x27
        0x94, // 0x28
        0xa4, // 0x29
        0x93, // 0x2a
        0xa4, // 0x2b
        0x93, // 0x2c
        0x93, // 0x2d
        0x92, // 0x2e
        0x92, // 0x2f
        0x80, // 0x30
        0x80, // 0x31
        0x80, // 0x32
        0x80, // 0x33
        0x80, // 0x34
        0x80, // 0x35
        0x80, // 0x36
        0x80, // 0x37
        0x80, // 0x38
        0x80, // 0x39
        0x80, // 0x3a
        0x80, // 0x3b
        0x80, // 0x3c
        0x80, // 0x3d
        0x80, // 0x3e
        0x80, // 0x3f
        0x92, // 0x40
        0x92, // 0x41
        0x92, // 0x42
        0x92, // 0x43
        0x92, // 0x44
        0x92, // 0x45
        0x92, // 0x46
        0x92, // 0x47
        0x92, // 0x48
        0x92, // 0x49
        0x92, // 0x4a
        0x92, // 0x4b
        0x92, // 0x4c
        0x92, // 0x4d
        0x92, // 0x4e
        0x92, // 0x4f
        0x80, // 0x50
        0x94, // 0x51
        0x94, // 0x52
        0x94, // 0x53
        0x94, // 0x54
        0x94, // 0x55
        0x94, // 0x56
        0x94, // 0x57
        0x94, // 0x58
        0x94, // 0x59
        0x93, // 0x5a
        0x94, // 0x5b
        0x94, // 0x5c
        0x94, // 0x5d
        0x94, // 0x5e
        0x94, // 0x5f
        0x92, // 0x60
        0x92, // 0x61
        0x92, // 0x62
        0x93, // 0x63
        0x93, // 0x64
        0x93, // 0x65
        0x93, // 0x66
        0x93, // 0x67
        0x93, // 0x68
        0x93, // 0x69
        0x93, // 0x6a
        0x93, // 0x6b
        0x94, // 0x6c
        0x94, // 0x6d
        0x92, // 0x6e
        0x93, // 0x6f
        0x94, // 0x70
        0x80, // 0x71
        0x80, // 0x72
        0x80, // 0x73
        0x93, // 0x74
        0x93, // 0x75
        0x93, // 0x76
        0x80, // 0x77
        0x80, // 0x78
        0x80, // 0x79
        0x40, // 0x7a
        0x80, // 0x7b
        0x94, // 0x7c
        0x94, // 0x7d
        0x42, // 0x7e
        0xa3, // 0x7f
        0x80, // 0x80
        0x80, // 0x81
        0x80, // 0x82
        0x80, // 0x83
        0x80, // 0x84
        0x80, // 0x85
        0x80, // 0x86
        0x80, // 0x87
        0x80, // 0x88
        0x80, // 0x89
        0x80, // 0x8a
        0x80, // 0x8b
        0x80, // 0x8c
        0x80, // 0x8d
        0x80, // 0x8e
        0x80, // 0x8f
        0xa0, // 0x90
        0xa0, // 0x91
        0xa0, // 0x92
        0xa0, // 0x93
        0xa0, // 0x94
        0xa0, // 0x95
        0xa0, // 0x96
        0xa0, // 0x97
        0xa0, // 0x98
        0xa0, // 0x99
        0xa0, // 0x9a
        0xa0, // 0x9b
        0xa0, // 0x9c
        0xa0, // 0x9d
        0xa0, // 0x9e
        0xa0, // 0x9f
        0x80, // 0xa0
        0x80, // 0xa1
        0x80, // 0xa2
        0x92, // 0xa3
        0xa2, // 0xa4
        0xa2, // 0xa5
        0x80, // 0xa6
        0x80, // 0xa7
        0x80, // 0xa8
        0x80, // 0xa9
        0x80, // 0xaa
        0xa2, // 0xab
        0xa2, // 0xac
        0xa2, // 0xad
        0xe0, // 0xae
        0x92, // 0xaf
        0xa0, // 0xb0
        0xa2, // 0xb1
        0x92, // 0xb2
        0xa2, // 0xb3
        0x92, // 0xb4
        0x92, // 0xb5
        0x90, // 0xb6
        0x91, // 0xb7
        0x92, // 0xb8
        0x80, // 0xb9
        0xca, // 0xba
        0xa2, // 0xbb
        0x92, // 0xbc
        0x92, // 0xbd
        0x90, // 0xbe
        0x91, // 0xbf
        0xa0, // 0xc0
        0xa2, // 0xc1
        0x94, // 0xc2
        0xa3, // 0xc3
        0x91, // 0xc4
        0x80, // 0xc5
        0x94, // 0xc6
        0xd3, // 0xc7
        0x80, // 0xc8
        0x80, // 0xc9
        0x80, // 0xca
        0x80, // 0xcb
        0x80, // 0xcc
        0x80, // 0xcd
        0x80, // 0xce
        0x80, // 0xcf
        0x94, // 0xd0
        0x93, // 0xd1
        0x93, // 0xd2
        0x93, // 0xd3
        0x93, // 0xd4
        0x93, // 0xd5
        0xa3, // 0xd6
        0x80, // 0xd7
        0x93, // 0xd8
        0x93, // 0xd9
        0x93, // 0xda
        0x93, // 0xdb
        0x93, // 0xdc
        0x93, // 0xdd
        0x93, // 0xde
        0x93, // 0xdf
        0x93, // 0xe0
        0x93, // 0xe1
        0x93, // 0xe2
        0x93, // 0xe3
        0x93, // 0xe4
        0x93, // 0xe5
        0x94, // 0xe6
        0xa3, // 0xe7
        0x93, // 0xe8
        0x93, // 0xe9
        0x93, // 0xea
        0x93, // 0xeb
        0x93, // 0xec
        0x93, // 0xed
        0x93, // 0xee
        0x93, // 0xef
        0x94, // 0xf0
        0x93, // 0xf1
        0x93, // 0xf2
        0x93, // 0xf3
        0x93, // 0xf4
        0x93, // 0xf5
        0x93, // 0xf6
        0x80, // 0xf7
        0x93, // 0xf8
        0x93, // 0xf9
        0x93, // 0xfa
        0x93, // 0xfb
        0x93, // 0xfc
        0x93, // 0xfd
        0x93, // 0xfe
        0x80, // 0xff
};

// static uint64_t extension_1op_table = 0xaaa9aaa24055a558;

static uint64_t extension_1op_table = 0x155a55a5aaaa6aaa;

static inline uint32_t opcode1byte_extension_lookup(uint8_t tblp, uint8_t moderm_reg)
{
    uint32_t tblp_t = tblp;
    uint32_t moderm_reg_t = moderm_reg;
    tblp_t = (tblp_t >> 4) & 0x3;
    uint32_t shift = tblp_t * 16;
    shift += moderm_reg_t * 2;
    uint64_t res = extension_1op_table >> shift;
    return res & 0x3;
}

static uint32_t normal_2op_table = 0xa051a;

static inline uint32_t opcode2byte_normal_lookup(uint8_t tblp_t, uint8_t moderm_reg_t)
{
    uint32_t tblp = tblp_t;
    uint32_t moderm_reg = moderm_reg_t;
    uint32_t shift = tblp * 8;
    shift += moderm_reg * 2;
    uint32_t res = normal_2op_table >> shift;
    return res & 0x3;
}

static uint8_t extension_2op_table[16] = {
        0x5a,
        0x05,
        0x00,
        0xa9,
        0x08,
        0x00,
        0x5a,
        0x50,
        0x96,
        0x40,
        0x55,
        0x00,
        0,
        0,
        0,
        0};

#define _mm_set1_epi32(val) (__extension__(__m128i)(__v4si){val, val, val, val})

#define _mm_set_epi64x(val1, val2) (__extension__(__m128i)(__v2di){val2, val1})

#define _mm_cmpeq_epi8(val1, val2) ((__m128i)((__v16qi)val1 == (__v16qi)val2))

#define _mm_set1_epi64x(val1) (__extension__(__m128i)(__v2di){val1, val1})

#define _mm_set1_epi8(val1) (__extension__(__m128i)(__v16qi){ \
    val1, val1, val1, val1, val1, val1, val1, val1,           \
    val1, val1, val1, val1, val1, val1, val1, val1})

#define _mm_and_si128(val1, val2) ((__m128i)((__v2du)val1 & (__v2du)val2))

#define _mm_or_si128(val1, val2) ((__m128i)((__v2du)val1 | (__v2du)val2))

// extern __inline __m128i __attribute__((__gnu_inline__, __always_inline__, __artificial__)) _mm_loadu_si128 (__m128i_u const *__P)
// {
//     return *__P;
// }

#define _mm256_set1_epi64x(val1) (__extension__(__m256i)(__v4di){val1, val1, val1, val1})

#define _mm256_set1_epi8(val1) (__extension__(__m256i)(__v32qi){ \
    val1, val1, val1, val1, val1, val1, val1, val1,              \
    val1, val1, val1, val1, val1, val1, val1, val1,              \
    val1, val1, val1, val1, val1, val1, val1, val1,              \
    val1, val1, val1, val1, val1, val1, val1, val1})

#define _mm256_and_si256(val1, val2) ((__m256i)((__v4du)val1 & (__v4du)val2))

#define _mm256_or_si256(val1, val2) ((__m256i)((__v4du)val1 | (__v4du)val2))

#define _mm256_cmpeq_epi8(val1, val2) ((__m256i)((__v32qi)val1 == (__v32qi)val2))

static inline uint32_t opcode2byte_extension_lookup(uint8_t tblp_t, uint8_t moderm_reg_t)
{
    uint32_t tblp = tblp_t;
    uint32_t moderm_reg = moderm_reg_t;
    __m128i num = (__m128i)__builtin_ia32_lddqu((char const *)extension_2op_table);
    uint32_t idx = ((tblp * 2)) | ((tblp * 2 + 1) << 8);
    __m128i res = (__m128i)__builtin_ia32_pshufb128((__v16qi)num, (__v16qi)_mm_set1_epi32((int)idx));
    uint32_t ans = (uint32_t)res[0];
    ans = ans >> moderm_reg * 2;
    return ans & 0x3;
}

/**
 * @brief cselect for uint32_t types
 * must be manually inspected to ensure the compiler generates CMOVcc family instructions
 * todo: transfer it to inline asm to 100% ensure
 *
 * @param pred
 * @param old_val
 * @param new_val
 * @return uint32_t
 */
static inline uint32_t cselect(uint64_t pred, uint32_t old_val, uint32_t new_val)
{
    // asm(".intel_syntax noprefix\n" 
    //         "cmp %1, 0\n"
    //         "cmovne %0, %2"
    //         : "+rm"(new_val)
    //         : "rm"(pred), "rm"(old_val));
    return pred?old_val:new_val;
}
//#endif

static inline int32_t cselect32(uint64_t pred, int32_t old_val, int32_t new_val)
{
    // asm(".intel_syntax noprefix\n"
    //         "cmp %1, 0\n"
    //         "cmovne %0, %2"
    //         : "+rm"(new_val)
    //         : "rm"(pred), "rm"(old_val));
    return pred?old_val:new_val;
}
static inline uint64_t cselect64(uint64_t pred, const uint64_t expected, uint64_t old_val, uint64_t new_val) __attribute__((always_inline));
/**
 * @brief cselect for uint64_t types
 * must be manually inspected to ensure the compiler generates CMOVcc family instructions
 * todo: transfer it to inline asm to 100% ensure
 *
 * @param pred
 * @param old_val
 * @param new_val
 * @return uint64
 */
static inline uint64_t cselect64(uint64_t pred, const uint64_t expected, uint64_t old_val, uint64_t new_val)
{
    // __asm__("cmp %1, %3\n\t"
    //         "cmove %0, %2"
    //         : "+rm"(new_val)
    //         : "rm"(pred), "rm"(old_val), "irm"(expected));
    return pred == expected?old_val:new_val;
}

static inline int64_t cselect64s(uint64_t pred, int64_t old_val, int64_t new_val)
{
    // __asm__("cmp %1, 0\n\t"
    //         "cmovne %0, %2"
    //         : "+rm"(new_val)
    //         : "rm"(pred), "rm"(old_val));
    return pred?old_val:new_val;
}

/**
 * @brief load a value as uint64_t from given address
 *
 * @param ptr
 * @return uint64
 */
static inline uint64_t load_u64(__m128i instr_data)
{
    return (uint64_t)instr_data[0];
}

/**
 * @brief load a value as uint8_t from given address with idx(secret)
 * Normally it will leak the idx if we load the exact result as uint8_t
 * So we read the whole uint64_t and use safe shift ops to hide the idx
 *
 * @param ptr
 * @param idx secret, ensured won't out of bounds
 * @return uint8_t
 */
static inline uint8_t load_u8_idx(uint8_t *ptr, uint8_t idx)
{
    return (uint8_t)((*((uint64_t *)ptr)) >> 8 * (idx)) & 0xff;
}

/**
 * @brief load an uint32_t from a given address and idx
 * Noted the range of idx is [0, 15], so the uint32_t may not be aligned
 * Also we need to hide the idx as secret, and extract/shift for __m128 requires an IMM8, not a register value
 * So we have to use shuffle here
 * Can also try the commented code above, which uses pure uint64_t to do the same thing
 *
 * @param ptr
 * @param idx secret
 * @return uint32
 */
static inline uint32_t load_mm_u32(__m128i instr_data, uint8_t idx_t)
{
    uint64_t idx = idx_t;
    __m128i num = instr_data;
    uint64_t query = 0x8080808000000000 | (idx) | ((idx + 1) << 8) | (idx + 2) << 16 | (idx + 3) << 24;
    __m128i query128 = _mm_set_epi64x((long long)0x8080808080808080, (long long)query);
    __m128i res = (__m128i)__builtin_ia32_pshufb128((__v16qi)num, (__v16qi)query128);
    return (uint32_t)res[0];
}

/**
 * @brief  load an uint8_t from a given address and idx
 *  Similar as load_u32, but much easier
 * @param ptr
 * @param idx secret
 * @return uint8_t
 */
static inline uint8_t load_mm_u8(__m128i instr_data, uint8_t idx)
{
    __m128i num = instr_data;
    uint64_t query = 0x8080808080808000 | idx;
    __m128i query128 = _mm_set_epi64x((long long)0x8080808080808080, (long long)query);
    __m128i res = (__m128i)__builtin_ia32_pshufb128((__v16qi)num, (__v16qi)query128);
    return (uint8_t)res[0];
}

/**
 * @brief Store an uint32_t into a given idx
 * normally this method will leak the idx, but here we use a fixed index in the output array, so no information leaked
 *
 * @param ptr
 * @param idx
 * @param val
 */
static inline void store_u32(uint8_t *ptr, uint8_t idx, uint32_t val)
{
    uint32_t *pptr = (uint32_t *)(ptr + idx);
    *pptr = val;
}

/**
 * @brief Check wether a given prefix pattern exists in the given data
 *   refer to `standard` table encoding for pattern info
 *   Many prefix are like yes or not booleans, so we only needs whether it exists or not
 *
 * @param data
 * @param target_prefix
 * @return uint32
 */
static inline uint32_t check_prefix(uint64_t data, uint64_t target_prefix)
{
    uint64_t res = (uint64_t)_mm_cmpeq_epi8(_mm_set_epi64x(~0, (long long)data), _mm_set_epi64x(0, (long long)target_prefix))[0];
    uint32_t ans = cselect(res == 0, 0, 1);
    return ans;
}

/**
 * @brief lookup prefix & opcode 1 in one batch
 *
 * Each byte is corresponding to an element in the `standard` table
 * We use high 4 bits to serach for blocks, each block has 16 elements, so the lower 4 bits are indexs to search for the exact element in one block
 *
 * @param prs the lower 6 bytes are valid(at most 5 bytes prefix + 1 byte opcode)
 * @return uint64_t The lower 6 bytes are valid, others should be 0
 */
static inline uint64_t prefix_op1_lookup(uint64_t prs)
{
    __m128i query = _mm_set1_epi64x((long long)prs);
    __m128i *table = (__m128i *)standard;
    uint64_t ans = 0;
    __m128i mask = _mm_set1_epi8((char)0xf0);
    __m128i op1_h4b = _mm_and_si128(mask, query);
    __m128i op1_l4b = _mm_andnot_si128(mask, query);
    for (char i = 0; i < 16; i++)
    {
        __m128i rmask = _mm_cmpeq_epi8(op1_h4b, _mm_set1_epi8((char)(i << 4)));
        // here another way is to use _mm_andnot_si128, I tried on test server, doesn't have much differences
        rmask = (__m128i)_mm_andnot_si128((__v2di)rmask, (__v2di)_mm_set1_epi8((char)0x80));
        rmask = _mm_or_si128(rmask, op1_l4b);
        __m128i tb = _mm_loadu_si128(table + i);
        __m128i res = (__m128i)__builtin_ia32_pshufb128((__v16qi)tb, (__v16qi)rmask);
        ans |= (uint64_t)res[0];
    }
    return ans & 0x0000ffffffffffff;
}

/**
 * @brief lookup opcode 2 in one batch
 *
 * Each byte is corresponding to an element in the `extended` table
 * We use high 4 bits to serach for blocks, each block has 16 elements, so the lower 4 bits are indexs to search for the exact element in one block
 *
 * @param op2 the lower 1 byte is valid(at most 1 byte opcode 2)
 * @return uint8_t Table look up result
 */
static inline uint8_t op2_lookup(uint8_t op2)
{
    __m128i *table = (__m128i *)extended;
    uint64_t ans = 0;
    for (uint64_t i = 0; i < 16; i++)
    {
        // since we only need to lookup 1 byte, use this(uint8_t) have no instruction number diff in binary
        uint8_t rmask = (uint8_t)cselect((op2 >> 4) == i, 0x00, 0x80);
        __m128i tb = _mm_loadu_si128(table + i);
        __m128i res = (__m128i)__builtin_ia32_pshufb128((__v16qi)tb, (__v16qi)_mm_set1_epi8((char)(rmask | (op2 & 0xf))));
        ans |= (uint64_t)res[0];
    }
    return (uint8_t)ans;
}

static inline __m128i prefix_op1_op2_lookup(uint64_t op1)
{
    __m256i query = _mm256_set1_epi64x((long long)op1);
    __m128i *table1 = (__m128i *)standard;
    __m128i *table2 = (__m128i *)extended;
    __m256i mask = _mm256_set1_epi8((char)0xf0);
    __m256i op1_h4b = _mm256_and_si256(mask, query);
    __m256i op1_l4b = (__m256i)_mm256_andnot_si256((__v4di)mask, (__v4di)query);
    uint64_t ans1 = 0;
    uint64_t ans2 = 0;
    for (uint64_t i = 0; i < 16; i++)
    {
        __m256i rmask = _mm256_cmpeq_epi8(op1_h4b, _mm256_set1_epi8((char)(i << 4)));
        // here another way is to use _mm_andnot_si128, I tried on test server, doesn't have much differences
        rmask = (__m256i)_mm256_andnot_si256(rmask, _mm256_set1_epi8((char)0x80));
        rmask = _mm256_or_si256(rmask, op1_l4b);
        __m128i tb1 = _mm_loadu_si128(table1 + i);
        __m128i tb2 = _mm_loadu_si128(table2 + i);
        __m256i tb12 = (__m256i)_mm256_insertf128_si256(_mm256_castsi128_si256((__v4si)tb1), (__v4si)tb2, 1);
        __m256i res = (__m256i)__builtin_ia32_pshufb256((__v32qi)tb12, (__v32qi)rmask);
        ans1 |= (uint64_t)res[0];
        ans2 |= (uint64_t)res[2];
    }
    return _mm_set_epi64x((long long)ans2, ans1 & 0x0000ffffffffffff);
}

/**
 * @brief Constant-time read the register value while hiding the register we actually read
 * Since AVX2 doesn't support much for uint64, we need to manually do it
 *
 * @param ctx
 * @param idx
 * @return uint64_t
 */
static uint64_t register_value_select(sgx_cpu_context_t *ctx, uint32_t idx)
{
    uint64_t ans = 0;
    #ifndef CT_VERIFY
    ans = cselect64(idx, 0x0, ctx->rax, ans);
    ans = cselect64(idx, 0x1, ctx->rcx, ans);
    ans = cselect64(idx, 0x2, ctx->rdx, ans);
    ans = cselect64(idx, 0x3, ctx->rbx, ans);
    ans = cselect64(idx, 0x4, ctx->rsp, ans);
    ans = cselect64(idx, 0x5, ctx->rbp, ans);
    ans = cselect64(idx, 0x6, ctx->rsi, ans);
    ans = cselect64(idx, 0x7, ctx->rdi, ans);
    ans = cselect64(idx, 0x8, ctx->r8, ans);
    ans = cselect64(idx, 0x9, ctx->r9, ans);
    ans = cselect64(idx, 0xa, ctx->r10, ans);
    ans = cselect64(idx, 0xb, ctx->r11, ans);
    ans = cselect64(idx, 0xc, ctx->r12, ans);
    ans = cselect64(idx, 0xd, ctx->r13, ans);
    ans = cselect64(idx, 0xe, ctx->r14, ans);
    ans = cselect64(idx, 0xf, ctx->r15, ans);
    #endif
    return ans;
}

/**
 *  To fix github issue https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/10
 *  Always load 2 pages data and combine together
 *  After discussion, we decide not to provide the mitigation for the instruction really across the page
 * @param ptr
 * @return
 */
static inline __m128i load_cross_page(uint8_t* ptr){
    uint8_t *rip_pfn = (uint8_t *) (((uint64_t) ptr) & (uint64_t)(~0xFFF));
    uint8_t *rip_idx = (uint8_t *) (((uint64_t)ptr) & 0xFFF);

    // the data is the original data 8 bytes from the target memory
    // first ensure it doesn't cross a page boundary
    int64_t rip_idx_masked = cselect64s((uint64_t) rip_idx <= (4096 - 16), (int64_t) rip_idx, 4096 - 16);
    __m128i_u *  loc = (__m128i_u *) ((uint64_t) rip_pfn | (uint64_t)rip_idx_masked);
    __m128i data = _mm_loadu_si128(loc);

    // finally combine both as needed
    uint32_t shift_amount = cselect((uint64_t) rip_idx > (4096 - 16), 16 - (uint32_t)(4096 - (uint64_t)rip_idx), 0);
    //we need to make a _m256i first then do the shift
    //suppose if it across the page, we just pad with 0x00
    data = data << shift_amount;
    return data;
}

/**
 * @brief our function to disassemble one instruction from the given input
 * One x64 instruction has at most 15 bytes, and our current output takes 12 bytes
 *
 */
int ct_decode(sgx_cpu_context_t *ctx, uint64_t *addr)
{

    //save & protect the status of ymm/zmm registers
    __m512i mm_regs[NUM_MM_REGS];

    //read input instruction: https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/10
    //we need to properly handle the cross page read
    uint8_t *input = (uint8_t *)(ctx->rip);
    uint8_t *rip_pfn = (uint8_t *) (((uint64_t) input) & (uint64_t)(~0xFFF));
    uint8_t *rip_idx = (uint8_t *) (((uint64_t)input) & 0xFFF);

    // the data is the original data 8 bytes from the target memory
    // first ensure it doesn't cross a page boundary
    int64_t rip_idx_masked = cselect64s((uint64_t) rip_idx <= (4096 - 16), (int64_t) rip_idx, 4096 - 16);
    __m128i_u* loc = (__m128i_u *) ((uint64_t) rip_pfn | (uint64_t)rip_idx_masked);
    __m128i instr_data = _mm_loadu_si128(loc);

    // finally combine both as needed
    // this is also the K bytes that we failed to protect
    uint32_t shift_amount = cselect((uint64_t) rip_idx > (4096 - 16), 16 - (uint32_t)(4096 - (uint64_t)rip_idx), 0);
    //we need to make a _m256i first then do the shift
    //suppose if it across the page, we just pad with 0x00
    instr_data = instr_data << shift_amount;


    // the data is the original data 8 bytes from the target memory
    uint64_t data = load_u64(instr_data);
    // we do the table look up for its first 6 bytes
    __m128i op1op2 = prefix_op1_op2_lookup(data);
    uint64_t lktb = (uint64_t)op1op2[0];
    uint32_t rmmod = 0;
    uint32_t size = 0;
    uint32_t rex = 0;
    uint32_t extended_opcode = 0;
    uint32_t idx = 15;
    //fix for https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/14
    uint32_t lock_prefix = 0;
    uint32_t string_instruction = 0;
    uint32_t stack_instruction = 0;
    uint32_t stack_instruction_ext = 0;
    uint32_t operand_rewrite = 0;
// todo since on linux, the TLS offset is zero, there is no need to care about this value for now
#ifdef CTD_UNIT_TEST
    uint32_t fs_rewrite = 0;
    uint32_t gs_rewrite = 0;
#endif
    uint32_t addr_rewrite = 0;
    uint32_t effective_prefix_extension = 0;
    // We need to know the exact idx of our opcode 1
    // todo: come up with a way to remove this loop, some SIMD instructions that returns idx of a given value
    for (uint32_t i = 0; i < 6; i++)
    {
        uint64_t shift = (lktb >> (i * 8));
        // to avoid short-circuit evaluation, we need to combine everything into a number to cheat the compiler
        uint32_t fg2 = (shift & 0xc0) >= 0x80;
        uint32_t fg1 = (idx << 8) | fg2;
        idx = cselect(fg1 == 0xf01, i, idx);
    }

    // we move everything outside our loop as much as possible, then this can reduce the total number of instructions
    // `tblp` is the table lookup result of `op1`
    uint8_t tblp = (lktb >> (8 * idx)) & 0xff;
    uint8_t op1 = (uint8_t)(data >> (8 * idx));
    // rmmod is: 0 => no memory access 1 => memory read 2 => memory write
    rmmod = (tblp >> 2) & 0x3;
    // size is the memory access size: byte, word, dword, qward, ...
    size = tblp & 0x3;
    // check if it's escape opcode, use this as mask for op2
    extended_opcode = cselect(op1 == 0xf, 1, 0);
    //add support for string instrucitons
    //https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/9
    string_instruction = cselect((tblp & 0xf0) == 0xa0, 1, 0);
    //https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/14
    stack_instruction = cselect((tblp & 0xf0) == 0xb0, 1, 0);

    // now we can handle the prefixes with the help of idx
    uint64_t prefixes = lktb & (uint64_t)(0x000000ffffffffff >> ((5 - idx) * 8));
    // check prefixes, rex is special because if covers 0x40 - 0x4f
    rex = check_prefix(prefixes >> ((idx - 1) * 8), 0x4040404040404040);
    // todo: check if overflow can be observed, then we can optimize this out
    rex = cselect(rex, (data >> ((idx - 1) * 8)) & 0x4f, 0);
    // operand size rewrite
    operand_rewrite = check_prefix(prefixes, 0x2020202020202020);
    effective_prefix_extension = cselect(operand_rewrite, 1, effective_prefix_extension);
#ifdef CTD_UNIT_TEST
    // fs register rewrite
    fs_rewrite = check_prefix(prefixes, 0x1414141414141414);
    // gs register rewrite
    gs_rewrite = check_prefix(prefixes, 0x1515151515151515);
#endif
    addr_rewrite = check_prefix(prefixes, 0x3030303030303030);
    lock_prefix = check_prefix(prefixes, 0x0303030303030303);
    // f2 prefix check
    effective_prefix_extension = cselect(check_prefix(prefixes, 0x0101010101010101), 3, effective_prefix_extension);
    // f3 prefix check
    effective_prefix_extension = cselect(check_prefix(prefixes, 0x0202020202020202), 2, effective_prefix_extension);

    // now we need to do an op2 table look up
    uint8_t op2tb = (uint8_t)(op1op2[1] >> (idx + 1) * 8);
    // rm mod and memory access size
    uint32_t op2_rm = (op2tb >> 4) & 0x3;
    uint32_t op2_size = op2tb & 0x07;
    // use mask result to decide whether save these result
    rmmod = cselect(extended_opcode, op2_rm, rmmod);
    size = cselect(extended_opcode, op2_size, size);
    // we also need to update idx
    idx += extended_opcode;
    uint32_t idx_tail = 1;
    // we shift the idx to the modrm byte location(suppose it has)
    uint8_t modRM = load_mm_u8(instr_data, (uint8_t)(idx + 1));
    //idx_tail += cselect(rmmod == 0, 0, 1);
    // now we need to decompose mod rm
    uint8_t modRM_mod = (modRM >> 6) & (3);
    // for reg, in opcode extension, they works as identifier
    uint8_t modRM_reg = (modRM >> 3) & (7);

    uint8_t modRM_rm = modRM & (7);
    // create flags and save mod_rm info
    uint8_t mod_rm_mod = (uint8_t)((modRM_mod << 6) | modRM_rm);
    // one special case for modRM, is when mod isn't 3 and rm is 4, we need to revert rex bit, otherwise we need to add rex bit into modRM
    uint32_t big_fg = cselect(modRM_mod != 3, 1, 0);

    // below is the case we handle opcode extension for 1 byte
    rmmod = cselect((tblp >> 6) == 0x3, opcode1byte_extension_lookup(tblp, modRM_reg), rmmod);
    // call/push instructions under opcode 1 byte extension table
    uint32_t potential_stack_instruction = cselect(((modRM_reg == 2) | (modRM_reg == 3) | (modRM_reg == 6)) > 0, 1, 0);
    stack_instruction_ext = cselect(( (uint32_t)(op1<<4) | (uint32_t)((tblp >> 6) + potential_stack_instruction) ) == 0xff4, 1, 0);

    // below is the case we handle for normal unusual 2 byte opcode 0x7e, 0x1a, 0x1b
    uint32_t tmp_rm = opcode2byte_normal_lookup((uint8_t)op2_rm, (uint8_t)effective_prefix_extension);
    // the condtion to apply this is: we are in 2 byte opcode mode and the opcode is valid
    rmmod = cselect(((extended_opcode << 4) | (op2tb >> 6)) == 0x11, tmp_rm, rmmod);

    // below is the case we handle opcode extension for 2 byte opcode
    tmp_rm = opcode2byte_extension_lookup((op2tb >> 3) & 0x7, modRM_reg);
    // condition is : 2 byte opcode and extension mode
    rmmod = cselect(((extended_opcode << 4) | (op2tb >> 6)) == 0x13, tmp_rm, rmmod);
    rmmod = cselect(((extended_opcode << 12) | (uint32_t)((op2tb >> 6) << 8) | (uint32_t)(modRM_mod << 4) | (uint32_t)((op2tb >> 3) & 0x7)) >= 0x1333, 0, rmmod);

    // save the memory access info and size
    rmmod = cselect(modRM_mod == 3, 0, rmmod);

    // Constant time ops, we always need to do them
    uint8_t sib = load_mm_u8(instr_data, (uint8_t)(idx + 2));
    uint32_t mod0_rm5 = load_mm_u32(instr_data, (uint8_t)(idx + 2));
    uint32_t sib_base5_mod02 = load_mm_u32(instr_data, (uint8_t)(idx + 3));
    uint8_t sib_mod1 = load_mm_u8(instr_data, (uint8_t)(idx + 3));


    // remaining output
    uint32_t imm4 = 0;
    uint32_t sib_base = 0;
    uint32_t sib_index = 0xff;
    uint32_t sib_scale = 0xff;
    uint32_t imm1 = 0;

    // bit ops
    // when modRM_mod is 0 and modRM_rm is 5, it's displacement only
    imm4 = cselect(mod_rm_mod == 0x05, mod0_rm5, imm4);
    idx_tail += cselect(mod_rm_mod == 0x05, 4, 0);

    // when modRM_mod isn't 3 and modRM_rm is 4, means we have SIB byte
    sib_scale = cselect((big_fg << 8 | modRM_rm) == 0x104, (sib >> 6) & (3), sib_scale);
    idx_tail += cselect((big_fg << 8 | modRM_rm) == 0x104, 1, 0);
    // we can apply rex directly, since no other special cases
    sib_index = cselect((big_fg << 8 | modRM_rm) == 0x104, ((sib >> 3) & 7) | ((rex & 0x2) << 2), sib_index);
    sib_base = cselect((big_fg << 8 | modRM_rm) == 0x104, (sib & 7) | ((rex & 0x1) << 3), sib_base);

    imm4 = cselect((big_fg << 16 | ((sib_base & 0x7) << 8) | mod_rm_mod) == 0x10504, sib_base5_mod02, imm4);
    idx_tail += cselect((big_fg << 16 | ((sib_base & 0x7) << 8) | mod_rm_mod) == 0x10504, 4, 0);
    imm1 = cselect((big_fg << 8 | mod_rm_mod) == 0x144, sib_mod1, imm1);
    idx_tail += cselect((big_fg << 8 | mod_rm_mod) == 0x144, 1, 0);
    imm4 = cselect((big_fg << 8 | mod_rm_mod) == 0x184, sib_base5_mod02, imm4);
    idx_tail += cselect((big_fg << 8 | mod_rm_mod) == 0x184, 4, 0);
    uint32_t small_fg = cselect(modRM_rm != 4, 1, 0);
    imm1 = cselect(((big_fg << 16) | (small_fg << 8) | modRM_mod) == 0x10101, sib, imm1);
    idx_tail += cselect(((big_fg << 16) | (small_fg << 8) | modRM_mod) == 0x10101, 1, 0);
    imm4 = cselect(((big_fg << 16) | (small_fg << 8) | modRM_mod) == 0x10102, mod0_rm5, imm4);
    idx_tail += cselect(((big_fg << 16) | (small_fg << 8) | modRM_mod) == 0x10102, 4, 0);
    // apply rex rewrite if necessary
    modRM_rm = (uint8_t)cselect(((big_fg << 8) | (uint32_t)modRM_rm) == 0x104, 0x4, modRM_rm | ((rex & 0x1) << 3));

    // This will be our final output
    uint64_t addr_ans = 0;
//#ifndef CTD_UNIT_TEST
    int64_t disp = (int64_t)((int8_t)imm1);
    disp = cselect64s(disp == 0, (int64_t)imm4, disp);

    // handle with the base register
    uint32_t base1 = cselect(mod_rm_mod == 0x04, 0xff, modRM_rm);
    sib_base = cselect(((uint32_t)(modRM_mod << 4) | (sib_base & 0x7)) == 0x5, 0xff, sib_base);
    uint32_t base = cselect(modRM_rm == 0x4, sib_base, base1);
    base = cselect(((modRM_mod << 4) | (modRM & (7))) == 0x05, 16, base);
    uint64_t base_val = register_value_select(ctx, base);
    base_val = cselect64(base, 16, ctx->rip, base_val);
    base_val = cselect64(base, 0xff, 0, base_val);
    base_val = cselect64(addr_rewrite, 1, (uint64_t)((uint32_t)base_val), base_val);
    addr_ans += base_val;

    // handle with the index register & the scale
    uint32_t index = cselect((sib_index) == 0x4, 0xff, sib_index);
    uint32_t scale = sib_scale;
    uint64_t index_val = register_value_select(ctx, index);
    index_val = cselect64(index, 16, ctx->rip, index_val);
    index_val = cselect64(index, 0xff, 0, index_val);
    index_val = cselect64(addr_rewrite, 1, (uint64_t)((uint32_t)index_val), index_val);
    uint64_t scale_val = (uint64_t)(1 << scale);
    addr_ans += index_val * scale_val;

    idx_tail += cselect(rmmod == 0, 0, 1);
    // add the displacement
    addr_ans = (uint64_t)((int64_t)addr_ans + disp);
    //special case handler for string related instructions
    addr_ans = cselect64(string_instruction, 1, register_value_select(ctx, (((uint32_t)tblp>>2) & 0xf) + 0x6 ), addr_ans);
    rmmod = cselect(string_instruction, ((uint32_t)tblp & 0x3) + 1, rmmod); //either read or write, no no-access
    rmmod = cselect(stack_instruction | stack_instruction_ext, 2, rmmod);
    addr_ans = cselect64(stack_instruction | stack_instruction_ext, 1, register_value_select(ctx, 4), addr_ans);
    rmmod = cselect(rmmod + lock_prefix > 2, 1, rmmod);
    idx_tail = cselect(stack_instruction | string_instruction, 1, idx_tail);
    idx_tail = cselect(stack_instruction_ext, 2, idx_tail);
//#endif
    //fix cross page padding: https://github.com/intel-collab/frameworks.security.sgx.ku-leuven-aex-notify/issues/10
    // idx will always be the length of prefixes + opcodes -1
    // idx_tail starting with 1, then includes the length of the rest: modRM, sib, disp
    // we won't have IMM lengths, luckily they are not affect much about address accessing
    // still under testing the case: IMM may have affect on memory accessing
    uint32_t inst_length = idx + idx_tail;
    // write the final output to the memory
    //todo block when rmmod isn't none and inst_length > K
    rmmod = cselect((rmmod & (inst_length + shift_amount < 17)) != 0, rmmod, rmmod);
    *addr = addr_ans;

    return (int)rmmod;
}

#define DUDECT_IMPLEMENTATION


#define SECRET_LEN_BYTES (16)


/* this will be called over and over */
uint8_t do_one_computation(uint8_t *data) {
    uint64_t ans;
    sgx_cpu_context_t sgx;
    for (int i = 0; i < 18; i++)
    {
        uint64_t *a = (uint64_t*) &sgx;
        a[i] = i + 1;
    }
    sgx.rip = (uint64_t)data;
    return ct_decode(&sgx, &ans);
}

/* called once per number_measurements */
void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
  randombytes(input_data, c->number_measurements * c->chunk_size);
  for (size_t i = 0; i < c->number_measurements; i++) {
    /* it is important to randomize the class sequence */
    classes[i] = randombit();
    if (classes[i] == 0) {
      memset(input_data + (size_t)i * c->chunk_size, 0x00, c->chunk_size);
    } else {
      // leave random
    }
  }
}

int run_test(void) {
  dudect_config_t config = {
      .chunk_size = SECRET_LEN_BYTES,
      #ifdef MEASUREMENTS_PER_CHUNK
      .number_measurements = MEASUREMENTS_PER_CHUNK,
      #else
      .number_measurements = 5000000,
      #endif
  };
  dudect_ctx_t ctx;

  dudect_init(&ctx, &config);

  /*
  Call dudect_main() until
   - returns something different than DUDECT_NO_LEAKAGE_EVIDENCE_YET, or
   - you spent too much time testing and give up
  Recommended that you wrap this program with timeout(2) if you don't
  have infinite time.
  For example this will run for 20 mins:
    $ timeout 1200 ./your-executable
  */
  dudect_state_t state = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
  while (state == DUDECT_NO_LEAKAGE_EVIDENCE_YET) {
    state = dudect_main(&ctx);
  }
  dudect_free(&ctx);
  return (int)state;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  run_test();
}