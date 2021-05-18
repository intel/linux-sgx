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

#ifndef EXAMPLE_UTILS_H
#define EXAMPLE_UTILS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dnnl.h"

#define CHECK(f) \
    do { \
        dnnl_status_t s_ = f; \
        if (s_ != dnnl_success) { \
            printf("[%s:%d] error: %s returns %d\n", __FILE__, __LINE__, #f, \
                    s_); \
            abort(); \
        } \
    } while (0)

#define CHECK_TRUE(expr) \
    do { \
        int e_ = expr; \
        if (!e_) { \
            printf("[%s:%d] %s failed\n", __FILE__, __LINE__, #expr); \
            abort(); \
        } \
    } while (0)

static dnnl_engine_kind_t parse_engine_kind(int argc, char **argv) {
    // Returns default engine kind, i.e. CPU, if none given
    if (argc == 1) {
        return dnnl_cpu;
    } else if (argc == 2) {
        // Checking the engine type, i.e. CPU or GPU
        char *engine_kind_str = argv[1];
        if (!strcmp(engine_kind_str, "cpu")) {
            return dnnl_cpu;
        } else if (!strcmp(engine_kind_str, "gpu")) {
            // Checking if a GPU exists on the machine
            if (!dnnl_engine_get_count(dnnl_gpu)) {
                printf("Application couldn't find GPU, please run with CPU instead. Thanks!\n");
                abort();
            }
            return dnnl_gpu;
        }
    }

    // If all above fails, the example should be ran properly
    printf("Please run example like this: %s cpu|gpu\n", argv[0]);
    abort();
}

// Read from memory, write to handle
static inline void read_from_dnnl_memory(void *handle, dnnl_memory_t mem) {
    dnnl_engine_t eng;
    dnnl_engine_kind_t eng_kind;
    const dnnl_memory_desc_t *md;

    CHECK(dnnl_memory_get_engine(mem, &eng));
    CHECK(dnnl_engine_get_kind(eng, &eng_kind));
    CHECK(dnnl_memory_get_memory_desc(mem, &md));
    size_t bytes = dnnl_memory_desc_get_size(md);

    if (eng_kind == dnnl_cpu) {
        void *ptr = NULL;
        CHECK(dnnl_memory_get_data_handle(mem, &ptr));
        if (ptr) {
            for (size_t i = 0; i < bytes; ++i) {
                ((char *)handle)[i] = ((char *)ptr)[i];
            }
        } else {
            handle = NULL;
        }
    }
#if DNNL_GPU_RUNTIME == DNNL_RUNTIME_OCL
    else if (eng_kind == dnnl_gpu) {
        dnnl_stream_t s;
        cl_command_queue q;
        cl_mem m;

        CHECK(dnnl_memory_get_ocl_mem_object(mem, &m));
        CHECK(dnnl_stream_create(&s, eng, dnnl_stream_default_flags));
        CHECK(dnnl_stream_get_ocl_command_queue(s, &q));

        cl_int ret = clEnqueueReadBuffer(
                q, m, CL_TRUE, 0, bytes, handle, 0, NULL, NULL);
        if (ret != CL_SUCCESS) {
            printf("clEnqueueReadBuffer failed.\nStatus Code: %d\n", ret);
            dnnl_stream_destroy(s);
            abort();
        }

        dnnl_stream_destroy(s);
    }
#endif
}

// Read from handle, write to memory
static inline void write_to_dnnl_memory(void *handle, dnnl_memory_t mem) {
    dnnl_engine_t eng;
    dnnl_engine_kind_t eng_kind;
    const dnnl_memory_desc_t *md;

    CHECK(dnnl_memory_get_engine(mem, &eng));
    CHECK(dnnl_engine_get_kind(eng, &eng_kind));
    CHECK(dnnl_memory_get_memory_desc(mem, &md));
    size_t bytes = dnnl_memory_desc_get_size(md);

    if (eng_kind == dnnl_cpu) {
        void *ptr = NULL;
        CHECK(dnnl_memory_get_data_handle(mem, &ptr));
        if (ptr) {
            for (size_t i = 0; i < bytes; ++i) {
                ((char *)handle)[i] = ((char *)ptr)[i];
            }
        } else {
            handle = NULL;
        }
    }
#if DNNL_GPU_RUNTIME == DNNL_RUNTIME_OCL
    else if (eng_kind == dnnl_gpu) {
        dnnl_stream_t s;
        cl_command_queue q;
        cl_mem m;

        CHECK(dnnl_memory_get_ocl_mem_object(mem, &m));
        CHECK(dnnl_stream_create(&s, eng, dnnl_stream_default_flags));
        CHECK(dnnl_stream_get_ocl_command_queue(s, &q));

        cl_int ret = clEnqueueWriteBuffer(
                q, m, CL_TRUE, 0, bytes, handle, 0, NULL, NULL);
        if (ret != CL_SUCCESS) {
            printf("clEnqueueWriteBuffer failed.\nStatus Code: %d\n", ret);
            dnnl_stream_destroy(s);
            abort();
        }

        dnnl_stream_destroy(s);
    }
#endif
}

#endif
