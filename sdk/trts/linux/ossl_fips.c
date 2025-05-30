/*
 * Copyright (C) 2011-2025 Intel Corporation. All rights reserved.
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

#ifdef __x86_64__

#include "util.h"
#include "elf_util.h"
#include "elf_parser.h"
#include "string.h"
#include "pthread.h"
#include "stdio/local.h"

extern void *get_enclave_base(void);
extern void do_atexit_aux(void);
extern void *__memcpy_chk(void *, const void *, size_t, size_t);
extern void *__memset_chk(void *, int, size_t, size_t);

static ElfW(Phdr)* get_phdr(const ElfW(Ehdr)* ehdr)
{
    if (ehdr == NULL)
        return NULL;

    /* check the ElfW Magic number. */
    if ((ehdr->e_ident[EI_MAG0] != ELFMAG0) ||
        (ehdr->e_ident[EI_MAG1] != ELFMAG1) ||
        (ehdr->e_ident[EI_MAG2] != ELFMAG2) ||
        (ehdr->e_ident[EI_MAG3] != ELFMAG3))
        return NULL;

    /* should be a shared object file. */
    if (ehdr->e_type != ET_DYN)
        return NULL;

    return GET_PTR(ElfW(Phdr), ehdr, ehdr->e_phoff);
}

static ElfW(Sym)* get_sym(ElfW(Sym)* symtab, size_t idx)
{
    if(STB_WEAK == ELFW(ST_BIND)(symtab[idx].st_info)
            && 0 == symtab[idx].st_value)
    {
        return NULL;
    }

    return &symtab[idx];
}

struct fips_sym_info {
    const char *name;
    void *addr;
};

static void* get_fips_sym_addr(const struct fips_sym_info *info, size_t nr_info, const char *sym_name)
{
    for (size_t i = 0; i < nr_info; i++)
    {
        if (0 == strcmp(sym_name, info[i].name))
        {
            return info[i].addr;
        }
    }
    return NULL;
}

char *__getenv(const char *name)
{
    (void)name;
    return NULL;
}
weak_alias(__getenv, getenv);

int __rdrand_for_fips(void)
{
    int r;
    __asm__ volatile (
            "1: rdrand  %0\n"
            "   jnc     1b\n"
            : "=r" (r)
            );
    return r;
}
weak_alias(__rdrand_for_fips, getpid);
weak_alias(__rdrand_for_fips, time);

extern char * strcpy(char *to, const char *from);

static int do_fips_relocs(const ElfW(Addr) fips_base,
        ElfW(Addr) rela_offset, size_t nr_relocs,
        ElfW(Addr) sym_offset, ElfW(Addr) str_offset)
{
    ElfW(Rela)* rela = GET_PTR(ElfW(Rela), fips_base, rela_offset);
    ElfW(Sym)*  symtab = GET_PTR(ElfW(Sym), fips_base, sym_offset);
    const char *strtab = GET_PTR(const char, fips_base, str_offset);
    ElfW(Sym)*  sym = NULL;
    const char *sym_name = NULL;
    struct fips_sym_info sym_info[] = {
        {"abort", &abort},
        {"getenv", &getenv},
        {"getpid", &getpid},
        {"memset", &memset},
        {"memcmp", &memcmp,},
        {"memcpy", &memcpy},
        {"memmove", &memmove},
        {"pthread_rwlock_init", &pthread_rwlock_init},
        {"pthread_rwlock_destroy", &pthread_rwlock_destroy},
        {"pthread_rwlock_rdlock", &pthread_rwlock_rdlock},
        {"pthread_rwlock_wrlock", &pthread_rwlock_wrlock},
        {"pthread_rwlock_unlock", &pthread_rwlock_unlock},
        {"pthread_key_create", &pthread_key_create},
        {"pthread_key_delete", &pthread_key_delete},
        {"pthread_self", &pthread_self},
        {"pthread_equal", &pthread_equal},
        {"pthread_once", &pthread_once},
        {"pthread_getspecific", &pthread_getspecific},
        {"pthread_setspecific", &pthread_setspecific},
        {"qsort", &qsort},
        {"strchr", &strchr},
        {"strcmp", &strcmp},
        {"strcpy", &strcpy},
        {"strlen", &strlen},
        {"strtol", &strtol},
        {"time", &time},
        {"__cxa_finalize", &do_atexit_aux},
        {"__memcpy_chk", &__memcpy_chk},
        {"__stack_chk_fail", &abort},
        {"__vfprintf_chk", &__vfprintf},
        {"__xpg_strerror_r", &strerror_r},
        {"__memset_chk", &__memset_chk}
    };

    for (size_t i = 0; i < nr_relocs; ++i, ++rela)
    {
        ElfW(Addr)* reloc_addr = GET_PTR(ElfW(Addr), fips_base, rela->r_offset);
        switch (ELF64_R_TYPE(rela->r_info))
        {
            case R_X86_64_RELATIVE:
                *reloc_addr = fips_base + (uintptr_t)rela->r_addend;
                break;
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                sym = get_sym(symtab, ELF64_R_SYM(rela->r_info));
                if (!sym)
                    break;
                sym_name = &strtab[sym->st_name];
                void *addr = get_fips_sym_addr(sym_info, sizeof(sym_info)/sizeof(sym_info[0]), sym_name);
                *reloc_addr = (ElfW(Addr))addr;
                break;
        }
    }
    return 0;
}

int relocate_fips_module(void* fips_base)
{
    ElfW(Half) phnum = 0;
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)fips_base;
    ElfW(Phdr) *phdr = get_phdr(ehdr);

    if (phdr == NULL)
        return -1;

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    {
        if (phdr->p_type == PT_DYNAMIC)
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);

            ElfW(Addr)   sym_offset = 0;
            ElfW(Addr)   str_offset = 0;
            ElfW(Addr)   rel_offset = 0;
            ElfW(Addr)   plt_offset = 0;

            size_t   rel_total_sz = 0;
            size_t   rel_entry_sz = 0;
            size_t   plt_total_sz = 0;

            for (count = 0; count < n_dyn; count++, dyn++)
            {
                if (dyn->d_tag == DT_NULL)  /* End */
                    break;

                switch (dyn->d_tag)
                {
                    case DT_STRTAB: /* string table */
                        str_offset = dyn->d_un.d_ptr;
                        break;

                    case DT_SYMTAB: /* symbol table */
                        sym_offset = dyn->d_un.d_ptr;
                        break;

                    case RTS_DT_REL:/* Rel (x86) or Rela (x64) relocs */
                        rel_offset = dyn->d_un.d_ptr;
                        break;

                    case RTS_DT_RELSZ:
                        rel_total_sz = dyn->d_un.d_val;
                        break;

                    case RTS_DT_RELENT:
                        rel_entry_sz = dyn->d_un.d_val;
                        break;

                    case DT_JMPREL: /* PLT relocs */
                        plt_offset = dyn->d_un.d_ptr;
                        break;

                    case DT_PLTRELSZ:
                        plt_total_sz = dyn->d_un.d_val;
                        break;
                }
            }

            if (rel_offset == 0 ||
                str_offset == 0 ||
                sym_offset == 0 ||
                plt_offset == 0 ||
                rel_total_sz == 0 ||
                rel_entry_sz == 0 ||
                plt_total_sz == 0)
            {
                return -1;
            }

            int ret = do_fips_relocs((const ElfW(Addr))fips_base, rel_offset, rel_total_sz/rel_entry_sz, sym_offset, str_offset);
            if (ret != 0)
                return -1;

            ret = do_fips_relocs((const ElfW(Addr))fips_base, plt_offset, plt_total_sz/rel_entry_sz, sym_offset, str_offset);
            if (ret != 0)
                return -1;
        }
    }

    return 0;
}

void *sgx_get_ossl_fips_sym(const char *symbol)
{
    void *enclave_base = get_enclave_base();
    uint64_t fips_base = (uint64_t)enclave_base +
                                get_aligned_enclave_segments_size((const void *)enclave_base);
    ElfW(Half) phnum = 0;
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr)*)fips_base;
    ElfW(Phdr) *phdr = get_phdr(ehdr);

    if (phdr == NULL)
        return NULL;

    ElfW(Addr)   sym_offset = 0;
    ElfW(Addr)   str_offset = 0;
    ElfW(Addr)   gnu_hash_offset = 0;

    for (; phnum < ehdr->e_phnum; phnum++, phdr++)
    {
        if (phdr->p_type == PT_DYNAMIC)
        {
            size_t      count;
            size_t      n_dyn = phdr->p_filesz/sizeof(ElfW(Dyn));
            ElfW(Dyn)   *dyn = GET_PTR(ElfW(Dyn), ehdr, phdr->p_paddr);

            for (count = 0; count < n_dyn; count++, dyn++)
            {
                if (dyn->d_tag == DT_NULL)  /* End */
                    break;

                switch (dyn->d_tag)
                {
                    case DT_STRTAB: /* string table */
                        str_offset = dyn->d_un.d_ptr;
                        break;

                    case DT_SYMTAB: /* symbol table */
                        sym_offset = dyn->d_un.d_ptr;
                        break;

                    case DT_GNU_HASH:   /* GNU style hash table */
                        gnu_hash_offset = dyn->d_un.d_ptr;
                        break;
                }
            }
            break;
        }
    }

    if (str_offset == 0 || sym_offset == 0 || gnu_hash_offset == 0)
    {
        return NULL;
    }

    ElfW(Sym)*  symtab = GET_PTR(ElfW(Sym), fips_base, sym_offset);
    const char *strtab = GET_PTR(const char, fips_base, str_offset);
    Elf_GNU_Hash_Header*  gnu_hash = GET_PTR(Elf_GNU_Hash_Header, fips_base, gnu_hash_offset);

    // Get the number of dynamic symbols by GNU hash table, since this number
    // is not directly defined by ELF spec. for unknown reasons.

    // The struct of GNU hash table is also not defined by the ELF spec, but it
    // looks like this:
    // struct gnu_hash_table {
    //     uint32_t nbuckets;
    //     uint32_t symoffset;
    //     uint32_t bloom_size;
    //     uint32_t bloom_shift;
    //     uint64_t bloom[bloom_size];
    //     uint32_t buckets[nbuckets];
    //     uint32_t chain[];
    // };

    // To find the number of dynamic symbols, we have to find a chain element
    // with the largest index. There are two steps involved:
    // (1) Find a chain that starts at the largest index, which is the largest
    //     element of buckets.
    // (2) Walk the chain to the end.

    uint32_t nbuckets = gnu_hash->gh_nbuckets;
    uint32_t symoffset = gnu_hash->gh_symndx;
    uint32_t bloom_size = gnu_hash->gh_maskwords;
    uint32_t *buckets = (uint32_t *)((uint64_t *)(++gnu_hash) + bloom_size);
    uint32_t *chain = &buckets[nbuckets];

    uint32_t max_idx = 0;
    for (uint32_t i = 0; i < nbuckets; i++)
    {
        if (max_idx < buckets[i])
            max_idx = buckets[i];
    }
    while ((chain[max_idx - symoffset] & 1) == 0)
    {
        max_idx++;
    }

    ElfW(Sym)* sym_end = symtab + max_idx;
    for (ElfW(Sym)*sym = sym_end; sym >= symtab; --sym)
    {
        if (strcmp(strtab + sym->st_name, symbol) == 0)
        {
            return (void *)((uint64_t)fips_base + (uint64_t)sym->st_value);
        }
    }
    return NULL;
}
#endif
