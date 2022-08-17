// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "errno.h"
#include "stdlib.h"
#include "string.h"
#include "util.h"
#include "sgx_error.h"
#include "se_trace.h"
#include "sgx_spinlock.h"
#include "sys/mman.h"

typedef struct _mapping
{
    uint64_t start;
    uint64_t end;
    uint8_t* status_vector;
    struct _mapping* next;
} _mapping_t;

static _mapping_t* _mappings;
static sgx_spinlock_t _lock;

static sgx_status_t _validate_mmap_parameters(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    sgx_status_t result = SGX_ERROR_INVALID_PARAMETER;
    int flags_copy = flags;

    // If addr is not NULL, then the kernel takes it as a hint about where to
    // place the mapping; on Linux, the kernel will pick a nearby page boundary
    // (but always above or equal to the value specified by
    // /proc/sys/vm/mmap_min_addr) and attempt to create the mapping there.
    // OE currently does not support this usage.
    if (addr != NULL)
    {
        // Previously, an error was raised in this case. To support more
        // use cases, the addr hint is ignored instead.
    }

    // PROT_NONE and PROT_EXEC are not supported.
    if (prot == PROT_NONE || (prot & PROT_EXEC))
    {
	SE_TRACE_ERROR("[mmap] unsupported `prot` value %d", prot);
        goto done;
    }

    if (length == 0)
    {
        SE_TRACE_ERROR("[mmap] length must be non zero");
        goto done;
    }

    enum
    {
        UNSUPPORTED,
        IGNORED,
        SUPPORTED
    };
    static struct support
    {
        int flag;
        int support;
    } flags_table[] = {
        {MAP_SHARED, SUPPORTED},
        {MAP_SHARED_VALIDATE, SUPPORTED},
        {MAP_PRIVATE, SUPPORTED},
#ifdef MAP_32BIT
        {MAP_32BIT, UNSUPPORTED},
#endif
        {MAP_ANON, SUPPORTED},
        {MAP_ANONYMOUS, SUPPORTED},
        {MAP_DENYWRITE, IGNORED /* by spec */},
        {MAP_EXECUTABLE, IGNORED /* by spec */},
        {MAP_FILE, IGNORED /* by spec */},
        {MAP_FIXED, UNSUPPORTED},
        {MAP_FIXED_NOREPLACE, UNSUPPORTED},
        {MAP_GROWSDOWN, UNSUPPORTED},
        {MAP_HUGETLB, UNSUPPORTED},
        {MAP_HUGE_2MB, UNSUPPORTED},
        {MAP_HUGE_1GB, UNSUPPORTED},
        {MAP_LOCKED, UNSUPPORTED},
        {MAP_NONBLOCK, IGNORED /* no special handling by OE */},
        {MAP_NORESERVE, IGNORED /* no special handling by OE */},
        {MAP_POPULATE, IGNORED /* no special handling by OE */},
        {MAP_STACK, IGNORED /* currently no-op on Linux */},
        {MAP_SYNC, IGNORED /* no special handling needed for OE */},
        // MUSL doesn't defined MAP_UNINITIALIZED
        // { MAP_UNINITIALIZED, SUPPORTED }
    };

    // Of the above flags, only MAP_FIXED is specified in POSIX.1-2001 and
    // POSIX.1-2008.  However, most systems also support MAP_ANONYMOUS.

    for (size_t i = 0; i < sizeof(flags_table)/sizeof(flags_table[0]); ++i)
    {
        if (flags_copy & flags_table[i].flag)
        {
            if (flags_table[i].support == UNSUPPORTED)
	    {
                SE_TRACE_ERROR("[mmap] unsupported `flag` value %d", flags_table[i].flag);
                goto done;
            }

            // Remove flag.
            flags_copy &= ~flags_table[i].flag;
        }
    }

    if (flags_copy)
    {
        SE_TRACE_ERROR("[mmap] invalid flag supplied");
        goto done;
    }

    // MAP_SHARED, MAP_SHARED_VALIDATE, MAP_PRIVATE are all treated the same
    // since an enclave is a single process. Exactly one of them must be
    // specified. They occupy the lower two bits of flags.
    if (!(flags & 0x03))
    {
        SE_TRACE_ERROR("[mmap] flags must specify exactly one of MAP_SHARED or MAP_SHARED_VALIDATE or MAP_PRIVATE\n");
        goto done;
    }

    if (flags & MAP_ANON || flags & MAP_ANONYMOUS)
    {
        // The fd argument is ignored; however, some implementations require fd
        // to be -1 if MAP_ANONYMOUS (or MAP_ANON) is specified. The offset
        // argument should be zero.
        if (offset != 0)
	{
            SE_TRACE_ERROR("[mmap] offset must be zero for anonymous mapping.");
            goto done;
        }
    }

    result = SGX_SUCCESS;
done:
    if (result != SGX_SUCCESS)
        errno = EINVAL;

    return result;
}

// See https://www.man7.org/linux/man-pages/man2/mmap.2.html for
// semantics of mmap and munmap.
void* _mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    void* ptr = NULL;
    uint8_t* vector = NULL;
    _mapping_t* m = NULL;
    size_t vector_length = 0;
    int ret = 0;

    if(_validate_mmap_parameters(addr, length, prot, flags, fd, offset))
    {
        SE_TRACE_ERROR("[mmap] invalid parameter\n");
        errno = EINVAL;
        goto done;	
    }

    // length is rounded up to nearest page size.
    length = ROUND_TO(length, SE_PAGE_SIZE);
    vector_length = ROUND_TO(length/8, 8);

    // Allocate objects.
    vector = (uint8_t*)calloc(vector_length, 1);
    m = (_mapping_t*)malloc(sizeof(*m));
    if (!vector || !m)
    {
        SE_TRACE_ERROR("[mmap] out of memory\n");
        errno = ENOMEM;
        goto done;	
    }

    if (((ret = posix_memalign(&ptr, SE_PAGE_SIZE, length)) != 0) || !ptr)
    {
        // posix_memalign does not set errno (by spec).
        // Set it ourselves.
        SE_TRACE_ERROR("[mmap] posix_memalign failed\n");
        errno = ret;
        goto done;	
    }

    // Set up mapping.
    m->start = (uint64_t)ptr;
    if(__builtin_add_overflow((uint64_t)m->start, length, (uint64_t*)&m->end))
    {
        SE_TRACE_ERROR("[mmap] ptr + length overflow\n");
        errno = EINVAL;
        goto done;
    }
    m->status_vector = vector;
    memset(ptr, 0, length);

    // Set relevant bits of status vector to 1.
    {
        int bv_idx = 0;
        uint8_t bit_mask = 0x01;
        // Since m->end has been rounded to SE_PAGE_SIZE and been validated via
        // oe_safe_add_u64, it is safe to add SE_PAGE_SIZE to `a` since it won't
        // overflow.
        for (uint64_t a = m->start; a < m->end; a += SE_PAGE_SIZE)
        {
            m->status_vector[bv_idx] |= bit_mask;
            bit_mask = (uint8_t)(bit_mask << 1);
            if (!bit_mask)
            {
                // Move to next byte in status vector.
                ++bv_idx;
                bit_mask = 0x01;
            }
        }
    }

    // Update mappings list.
    sgx_spin_lock(&_lock);
    m->next = _mappings;
    _mappings = m;
    sgx_spin_unlock(&_lock);

    errno = 0;
    result = SGX_SUCCESS;

done:
    if (result != SGX_SUCCESS)
    {
        if(vector) free(vector);
        if(ptr) free(ptr);
        if(m) free(m);
        return MAP_FAILED;
    }
    return ptr;
}

static void munmap_internal(
    _mapping_t* prev,
    _mapping_t* m,
    uint64_t start,
    uint64_t end)
{
    while (m)
    {
        bool delete_flag = true;
        if (end <= m->start || start >= m->end)
        {
            // Specified address range does not intersect with current mapping.
            prev = m;
            m = m->next;
            continue;
        }

        // Specified address range intersects with current mapping.

        // Unmap part of address range that lies to the left of current mapping.
        if (start < m->start)
            munmap_internal(m, m->next, start, m->start);

        // Unmap part of address range that lies to the right of current
        // mapping.
        if (end > m->end)
            munmap_internal(m, m->next, m->end, end);

        if (start > m->start || end < m->end)
        {
            // Partial unmapping.
            uint8_t bit_mask = (uint8_t)1;
            int bv_idx = 0;

            // Mark all pages in given address range as unmapped.
            for (uint64_t a = m->start; a < m->end; a += SE_PAGE_SIZE)
            {
                // If pages lies in the specified range, unset its status.
                if (start <= a && a < end)
                    m->status_vector[bv_idx] &= (uint8_t)(~bit_mask);

                bit_mask = (uint8_t)(bit_mask << 1);
                if (!bit_mask)
                {
                    // Retain the mapping if any bit in the vector is set.
                    delete_flag = delete_flag &&!m->status_vector[bv_idx];
                    bit_mask = 1;
                    bv_idx++;
                }
            }
            delete_flag = delete_flag &&!m->status_vector[bv_idx];
        }

        if (delete_flag)
        {
            if (prev)
                prev->next = m->next;
            else
                _mappings = m->next;
            free(m->status_vector);
            free((void*)m->start);
            free(m);
        }

        break;
    }
}

int _munmap(void* addr, uint64_t length)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    uint64_t start = (uint64_t)addr;
    uint64_t end = 0;

    if ((start % SE_PAGE_SIZE) != 0)
    {
        SE_TRACE_ERROR("[munmap] addr is invalid\n");
        errno = EINVAL;
        goto done;
    }

    if(__builtin_add_overflow(start, length, &end))
    {
        SE_TRACE_ERROR("[munmap] addr + length overflow\n");
        errno = EINVAL;
        goto done;
    }

    sgx_spin_lock(&_lock);
    munmap_internal(NULL, _mappings, start, end);
    sgx_spin_unlock(&_lock);
    errno = 0;
    result = SGX_SUCCESS;
done:
    return (result == SGX_SUCCESS) ? 0 : -1;
}

weak_alias(_mmap, mmap);
weak_alias(_mmap, mmap64);
weak_alias(_munmap, munmap);

