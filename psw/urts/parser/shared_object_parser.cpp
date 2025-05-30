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
#include "shared_object_parser.h"
#include "cpputil.h"
#include "se_trace.h"
#include "se_memcpy.h"
#include "global_data.h"
#include "metadata.h"
#include "util.h"
#include <sys/mman.h>
#include <vector>
#include <map>

namespace {
/** the callback function to filter a section.
 *
 * @shstrtab:  the section header string table
 * @shdr:      the current section header to be examined
 * @user_data: user supplied data for the callback
 *
 * @return: true if current section header is what we are looking for.
 */
typedef bool (* section_filter_f)(const char* shstrtab,
                                  const ElfW(Shdr)* shdr,
                                  const void* user_data);

bool compare_section_name(const char* shstrtab,
                          const ElfW(Shdr)* shdr,
                          const void* user_data)
{
    // `shstrtab + shdr->sh_name' is the section name.
    return (!strcmp(shstrtab + shdr->sh_name, (const char*)user_data));
}

bool compare_section_addr(const char* shstrtab,
                          const ElfW(Shdr)* shdr,
                          const void* user_data)
{
    UNUSED(shstrtab);
    return (shdr->sh_addr == (ElfW(Addr))(size_t)user_data);
}

const ElfW(Shdr)* get_section(const ElfW(Ehdr) *elf_hdr,
                              section_filter_f f,
                              const void* user_data)
{
    const ElfW(Shdr) *shdr = GET_PTR(ElfW(Shdr), elf_hdr, elf_hdr->e_shoff);
    assert(sizeof(ElfW(Shdr)) == elf_hdr->e_shentsize);

    // section header string table
    const char *shstrtab = GET_PTR(char, elf_hdr, shdr[elf_hdr->e_shstrndx].sh_offset);

    for (unsigned idx = 0; idx < elf_hdr->e_shnum; ++idx, ++shdr)
    {
        SE_TRACE(SE_TRACE_DEBUG, "section [%u] %s: sh_addr = %x, sh_size = %x, sh_offset = %x, sh_name = %x\n",
                 idx, shstrtab + shdr->sh_name, shdr->sh_addr, shdr->sh_size, shdr->sh_offset, shdr->sh_name);
        if (f(shstrtab, shdr, user_data))
            return shdr;
    }

    return NULL;
}

const ElfW(Shdr)* get_section_by_name(const ElfW(Ehdr) *elf_hdr, const char *name)
{
    return get_section(elf_hdr, compare_section_name, name);
}

const ElfW(Shdr)* get_section_by_addr(const ElfW(Ehdr) *elf_hdr, ElfW(Addr) start_addr)
{
    return get_section(elf_hdr, compare_section_addr, (const void*)(size_t)start_addr);
}

template <typename T>
const T* get_section_raw_data(const ElfW(Ehdr) *elf_hdr, ElfW(Addr) start_addr)
{
    const ElfW(Shdr)* shdr = get_section_by_addr(elf_hdr, start_addr);
    if (shdr == NULL)
        return NULL;

    return GET_PTR(T, elf_hdr, shdr->sh_offset);
}

bool validate_elf_header(const ElfW(Ehdr) *elf_hdr)
{
    // validate magic number
    if (memcmp(&elf_hdr->e_ident, ELFMAG, SELFMAG)) {
        SE_TRACE(SE_TRACE_ERROR, "Incorrect magic number\n");
        return false;
    }

#if RTS_SYSTEM_WORDSIZE == 64
    if (ELFCLASS64 != elf_hdr->e_ident[EI_CLASS]) {
        SE_TRACE(SE_TRACE_ERROR, "Expected ELFCLASS64: 0x%x\n",
                 elf_hdr->e_ident[EI_CLASS]);
        return false;
    }
#else
    if (ELFCLASS32 != elf_hdr->e_ident[EI_CLASS]) {
        SE_TRACE(SE_TRACE_ERROR, "Expected ELFCLASS32: 0x%x\n",
                 elf_hdr->e_ident[EI_CLASS]);
        return false;
    }
#endif

    if (ELFDATA2LSB!= elf_hdr->e_ident[EI_DATA]) {
        SE_TRACE(SE_TRACE_ERROR, "Expected ELFDATA2LSB: 0x%x\n",
                 elf_hdr->e_ident[EI_DATA]);
        return false;
    }

    if (EV_CURRENT != elf_hdr->e_ident[EI_VERSION]) {
        SE_TRACE(SE_TRACE_ERROR, "Expected EV_CURRENT: 0x%x\n",
                 elf_hdr->e_ident[EI_VERSION]);
        return false;
    }

    if (ET_DYN != elf_hdr->e_type) {
        SE_TRACE(SE_TRACE_ERROR, "Expected ET_DYN: 0x%x\n",
                 elf_hdr->e_type);
        return false;
    }

    if (sizeof(ElfW(Phdr)) != elf_hdr->e_phentsize) {
        SE_TRACE(SE_TRACE_ERROR, "Expected phentsize == %d, got %d\n",
                 sizeof(ElfW(Phdr)),
                 elf_hdr->e_phentsize);
        return false;
    }

    return true;
}

bool parse_dyn(const ElfW(Ehdr) *elf_hdr, ElfW(Dyn)* dyn_info)
{
    const ElfW(Phdr) *prg_hdr = GET_PTR(ElfW(Phdr), elf_hdr, elf_hdr->e_phoff);
    bool has_dyn = false;

    for (unsigned idx = 0; idx < elf_hdr->e_phnum; ++idx, ++prg_hdr)
    {
        if (PT_DYNAMIC == prg_hdr->p_type)
        {
            const ElfW(Dyn) *dyn_entry = GET_PTR(ElfW(Dyn), elf_hdr, prg_hdr->p_offset);

            // parse dynamic segment
            // An entry with a DT_NULL tag marks the end.
            while (dyn_entry->d_tag != DT_NULL)
            {
                SE_TRACE(SE_TRACE_DEBUG, "dynamic tag = %x, ptr = %x\n", dyn_entry->d_tag, dyn_entry->d_un.d_ptr);

                if (dyn_entry->d_tag < DT_NUM)
                {
                    memcpy_s(&dyn_info[dyn_entry->d_tag], sizeof(ElfW(Dyn)), dyn_entry, sizeof(ElfW(Dyn)));
                }
                else if (dyn_entry->d_tag > DT_ADDRRNGLO && dyn_entry->d_tag <= DT_ADDRRNGHI)
                {
                    memcpy_s(&dyn_info[DT_ADDRTAGIDX(dyn_entry->d_tag) + DT_NUM], sizeof(ElfW(Dyn)), dyn_entry, sizeof(ElfW(Dyn)));
                }

                dyn_entry++;
                has_dyn = true;
            }

            return has_dyn;
        }
    }

    return false;
}

bool do_validate_reltab(const ElfW(Rel) *reltab, size_t nr_rel)
{
    if (reltab == NULL && nr_rel != 0) return false;

#if RTS_SYSTEM_WORDSIZE == 64
    const ElfW(Rel) *rela = reltab;

    for (unsigned idx = 0; idx < nr_rel; idx++, rela++)
    {
        switch (ELF64_R_TYPE(rela->r_info))

        {
        case R_X86_64_RELATIVE:
            break;

        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_64:
            break;

        case R_X86_64_NONE:
            break;

        case R_X86_64_DTPMOD64:
        case R_X86_64_DTPOFF64:
        case R_X86_64_TPOFF64:
            break;
#else
    const ElfW(Rel) *rel = reltab;

    for (unsigned idx = 0; idx < nr_rel; idx++, rel++)
    {
        switch (ELF32_R_TYPE(rel->r_info))
        {
        case R_386_RELATIVE:    /* B+A */
            break;

        case R_386_GLOB_DAT:
        case R_386_JMP_SLOT:    /* S */
            break;

        case R_386_32:          /* S+A */
            break;

        case R_386_PC32:        /* S+A-P */
            break;

        case R_386_NONE:
            break;

        case R_386_TLS_DTPMOD32:
            break;

        case R_386_TLS_DTPOFF32:
            break;

        case R_386_TLS_TPOFF:
            break;

        case R_386_TLS_TPOFF32:
            break;
#endif

        default:    /* unsupported relocs */
            SE_TRACE(SE_TRACE_WARNING, "unsupported relocation type detected\n");
            return false;
        }
    }

    return true;
}

bool validate_reltabs(const ElfW(Ehdr) *elf_hdr, const ElfW(Dyn) *dyn_info)
{
#if RTS_SYSTEM_WORDSIZE == 64
    // The relocation struct must be rela on x64.
    if (dyn_info[DT_REL].d_un.d_ptr)
    {
        SE_TRACE(SE_TRACE_WARNING, "Rel struct detected on x64\n");
        return false;
    }
#else
    // The relocation struct must be rel on x86.
    if (dyn_info[DT_RELA].d_un.d_ptr)
    {
        SE_TRACE(SE_TRACE_WARNING, "Rela struct detected on x86\n");
        return false;
    }
#endif

    const ElfW(Rel) *reltab = get_section_raw_data<ElfW(Rel)>(elf_hdr, dyn_info[RTS_DT_REL].d_un.d_ptr);
    const ElfW(Word) reltab_sz = (ElfW(Word))dyn_info[RTS_DT_RELSZ].d_un.d_val;

    const ElfW(Rel) *jmpreltab = get_section_raw_data<ElfW(Rel)>(elf_hdr, dyn_info[DT_JMPREL].d_un.d_ptr);
    const ElfW(Word) jmpreltab_sz = (ElfW(Word))dyn_info[DT_PLTRELSZ].d_un.d_val;

    return (do_validate_reltab(reltab, reltab_sz / sizeof(ElfW(Rel)))
            && do_validate_reltab(jmpreltab, jmpreltab_sz / sizeof(ElfW(Rel))));
}

bool has_ctor_section(const ElfW(Ehdr) *elf_hdr)
{
    const ElfW(Shdr) *shdr = get_section_by_name(elf_hdr, ".ctors");
    if (NULL == shdr) return false;

    se_trace(SE_TRACE_ERROR, "ERROR: .ctors section is found, global initializers will not be invoked correctly!\n");
    return true;
}

bool validate_segment(const ElfW(Ehdr) *elf_hdr, uint64_t len)
{
    const ElfW(Phdr) *prg_hdr = GET_PTR(ElfW(Phdr), elf_hdr, elf_hdr->e_phoff);
    assert(sizeof(ElfW(Phdr)) == elf_hdr->e_phentsize);

    std::vector< std::pair<ElfW(Addr), ElfW(Addr)> > load_seg(elf_hdr->e_phnum, std::make_pair(0, 0));
    int k = 0;

    for (int idx = 0; idx < elf_hdr->e_phnum; idx++, prg_hdr++)
    {
        /* Validate the size of the buffer */
        if (len < (uint64_t)prg_hdr->p_offset + prg_hdr->p_filesz)
            return false;

        if (PT_LOAD == prg_hdr->p_type)
        {
            // The default align is max page size. On x86-64, the max page size is 2M, but EPC page size is 4K,
            // so in x86-64, we just treat it as EPC page size. The (2M - 4K) size is not eadded. We leave it
            // as a hole.
            if (!IS_PAGE_ALIGNED(prg_hdr->p_align))
            {
                SE_TRACE(SE_TRACE_WARNING, "A segment is not PAGE aligned, alignment = %x\n", prg_hdr->p_align);
                return false;
            }

            // Verify the overlap of segment.
            load_seg[k].first = prg_hdr->p_vaddr;
            load_seg[k].second = ROUND_TO(prg_hdr->p_vaddr + prg_hdr->p_memsz, prg_hdr->p_align) - 1;

            for (int j = 0; j < k; j++)
            {
                if (is_overlap(load_seg[k], load_seg[j]))
                {
                    SE_TRACE(SE_TRACE_WARNING, "there is overlap segment [%x : %x] [%x : %x]\n",
                             load_seg[k].first, load_seg[k].second, load_seg[j].first, load_seg[j].second);
                    return false;
                }

            }

            k++;
        }
    }
    return true;
}

si_flags_t page_attr_to_si_flags(uint32_t page_attr)
{
    si_flags_t res = SI_FLAG_REG;

    if (page_attr & PF_R)
        res |= SI_FLAG_R;

    if (page_attr & PF_W)
        res |= SI_FLAG_W;

    if (page_attr & PF_X)
        res |= SI_FLAG_X;

    return res;
}

Section* build_section(const uint8_t* raw_data, uint64_t size, uint64_t virtual_size,
                       uint64_t rva, uint32_t page_attr)
{
    si_flags_t sf = page_attr_to_si_flags(page_attr);

    if (sf != SI_FLAG_REG)
        return new Section(raw_data, size, virtual_size, rva, sf);

    return NULL;
}

bool build_regular_sections(const uint8_t* start_addr,
                            std::vector<Section *>& sections)
{
    const ElfW(Ehdr) *elf_hdr = (const ElfW(Ehdr) *)start_addr;
    const ElfW(Phdr) *prg_hdr = GET_PTR(ElfW(Phdr), start_addr, elf_hdr->e_phoff);
    uint64_t virtual_size = 0, alignment = 0, aligned_virtual_size = 0;
    unsigned section_count = 1; /* Definition only used with se_trace(SE_TRACE_DEBUG) below */

    for (unsigned idx = 0; idx < elf_hdr->e_phnum; ++idx, ++prg_hdr)
    {
        Section* sec = NULL;

        switch (prg_hdr->p_type)
        {
        case PT_LOAD:
            sec = build_section(GET_PTR(uint8_t, start_addr, prg_hdr->p_offset),
                                (uint64_t)prg_hdr->p_filesz, (uint64_t)prg_hdr->p_memsz,
                                (uint64_t)prg_hdr->p_vaddr, (uint32_t) prg_hdr->p_flags);
            se_trace(SE_TRACE_DEBUG, "LOAD Section: %d\n", section_count++);
            se_trace(SE_TRACE_DEBUG, "Flags = 0x%016lX\n", (uint64_t)prg_hdr->p_flags);
            se_trace(SE_TRACE_DEBUG, "VAddr = 0x%016lX\n", (uint64_t)prg_hdr->p_vaddr);
            se_trace(SE_TRACE_DEBUG, "Size  = 0x%016lX\n\n", (uint64_t)prg_hdr->p_memsz);
            break;

        case PT_TLS:
            virtual_size = (uint64_t)prg_hdr->p_memsz;
            alignment = (uint64_t)prg_hdr->p_align;

            /*  according to ELF spec, alignment equals zero or one means no align requirement */
            if (alignment == 0 || alignment == 1)
                aligned_virtual_size = virtual_size;
            else
                aligned_virtual_size = (virtual_size + alignment - 1) & (~(alignment - 1));

            sec = build_section(GET_PTR(uint8_t, start_addr, prg_hdr->p_offset),
                                (uint64_t)prg_hdr->p_filesz, aligned_virtual_size,
                                (uint64_t)prg_hdr->p_vaddr, (uint32_t) prg_hdr->p_flags);
            se_trace(SE_TRACE_DEBUG, "TLS Section: %d\n", section_count++);
            se_trace(SE_TRACE_DEBUG, "Flags = 0x%016lX\n", (uint64_t)prg_hdr->p_flags);
            se_trace(SE_TRACE_DEBUG, "VAddr = 0x%016lX\n", (uint64_t)prg_hdr->p_vaddr);
            se_trace(SE_TRACE_DEBUG, "Size  = 0x%016lX\n\n", (uint64_t)prg_hdr->p_memsz);
            break;

        default:
            continue;
        }

        if (sec == NULL)
            return false;

        sections.push_back(sec);
        continue;
    }

    return true;
}
}

SharedObjectParser::SharedObjectParser (const uint8_t* start_addr, uint64_t len)
    :m_start_addr(start_addr), m_len(len)
{
    memset(&m_dyn_info, 0, sizeof(m_dyn_info));
}

sgx_status_t SharedObjectParser::run_parser()
{
    /* We only need to run the parser once. */
    if (m_sections.size() != 0) return SGX_SUCCESS;

    const ElfW(Ehdr) *elf_hdr = (const ElfW(Ehdr) *)m_start_addr;
    if (elf_hdr == NULL || m_len < sizeof(ElfW(Ehdr))) {
        SE_TRACE_ERROR("Header invalid size\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }
    /* Check elf header*/
    if (!validate_elf_header(elf_hdr)) {
        SE_TRACE_ERROR("Header invalid\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    /* Check if there is any overlap segment, and make sure the segment is 1 page aligned;
    * TLS segment must exist.
    */
    if (!validate_segment(elf_hdr, m_len)) {
        SE_TRACE_ERROR("Segment incorrect\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    if (!parse_dyn(elf_hdr, &m_dyn_info[0])) {
        SE_TRACE_ERROR("Dyn incorrect\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }


    /* Check if there is unexpected relocation type */
    if (!validate_reltabs(elf_hdr, m_dyn_info)) {
        SE_TRACE_ERROR("Reltabs incorrect\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    /* Check if there is .ctor section */
    if (has_ctor_section(elf_hdr)) {
        SE_TRACE_ERROR("ctor section incorrect\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }

    /* build regular sections */
    if (build_regular_sections(m_start_addr, m_sections))
        return SGX_SUCCESS;
    else {
        SE_TRACE_ERROR("Regular sections incorrect\n");
        return SGX_ERROR_INVALID_ENCLAVE;
    }
}

SharedObjectParser::~SharedObjectParser()
{
    delete_ptrs_from_container(m_sections);
}

const uint8_t* SharedObjectParser::get_start_addr() const
{
    return m_start_addr;
}

uint64_t SharedObjectParser::get_len() const
{
    return m_len;
}

const std::vector<Section *>& SharedObjectParser::get_sections() const
{
    return m_sections;
}
