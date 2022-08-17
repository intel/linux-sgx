// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "sgx_stdc_ex_t.h"
#include "errno.h"
#include "sys/types.h"
#include "sys/limits.h"
#include "stdarg.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "unistd.h"
#include "sgx_trts.h"
#include "se_trace.h"

FILE* const stdin = ((FILE*)1);
FILE* const stdout = ((FILE*)2);
FILE* const stderr = ((FILE*)3);

int rename(const char* oldpath, const char* newpath)
{
    int ret = -1;

    errno = 0;

    if (u_rename(&ret, oldpath, newpath) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}
int remove(const char *pathname)
{
    int ret = -1;

    errno = 0;

    if (u_remove(&ret, pathname) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int sprintf(char *str, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int ret = vsnprintf(str, SIZE_MAX, format, ap);
    va_end(ap);
    return ret;
}
int vsprintf(char *str, const char *format, va_list ap)
{
    return vsnprintf(str, SIZE_MAX, format, ap);
}

int vfprintf(FILE *stream, const char* fmt, va_list ap_)
{
    char buf[256];
    char* p = buf;
    int n;
    char* new_buf = NULL;

    /* Try first with a fixed-length scratch buffer */
    {
        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);

        if (n < 0)
            goto done;

        if ((size_t)n < sizeof(buf))
        {
            u_fprintf(stream, p, (size_t)-1);
            goto done;
        }
    }

    /* If string was truncated, retry with correctly sized buffer */
    {
        if (!(new_buf = (char*)malloc((size_t)n + 1)))
            goto done;

        p = new_buf;

        va_list ap;
        va_copy(ap, ap_);
        n = vsnprintf(p, (size_t)n + 1, fmt, ap);
        va_end(ap);

        if (n < 0)
            goto done;

        u_fprintf(stream, p, (size_t)-1);
    }

done:

    if (new_buf)
        free(new_buf);

    return n;
}

int fprintf(FILE *stream, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int ret = vfprintf(stream, format, ap);
    va_end(ap);
    return ret;
}


int vprintf(const char* fmt, va_list ap_)
{
    return vfprintf(stdout, fmt, ap_);
}
int printf(const char* format, ...)
{
    va_list ap;
    int n;

    va_start(ap, format);
    n = vprintf(format, ap);
    va_end(ap);

    return n;
}

int fputs(const char *str, FILE *stream)
{
    errno = 0;
    size_t n = strlen(str)+1;
    if (u_fprintf(stream, str, n) != SGX_SUCCESS)
        return -1;
    return (int)n;
}
int puts(const char *str)
{
    return fputs(str, stdout);
}

char *fgets(char *s, int size, FILE *stream)
{
    char *ret = NULL;
    errno = 0;
    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fgets - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if(u_fgets(&ret, s, size, stream) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return NULL;
    }
    return ret ? s : NULL;
}

FILE *fopen(const char *pathname, const char *mode)
{
    FILE * ret = NULL;

    errno = 0;
    
    if (u_fopen(&ret, pathname, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if(!sgx_is_outside_enclave(ret, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fopen - return value should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    return ret;
}
FILE *fdopen(int fd, const char *mode)
{
    FILE *ret = 0;

    errno = 0;
    
    if (u_fdopen(&ret, fd, mode) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return NULL;
    }

    if(!sgx_is_outside_enclave(ret, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fdopen - return value should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }

    return ret;

}

int fclose(FILE *stream)
{
    int ret = 0;

    errno = 0;
    
    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fclose - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_fclose(&ret, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return -1;
    }

    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = 0;

    errno = 0;
    
    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fread - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_fread(&ret, ptr, size, nmemb, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return 0;
    }

    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t ret = 0;

    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fwrite - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if (u_fwrite(&ret, ptr, size, nmemb, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
        return 0;
    }

    return ret;
}

int fflush(FILE *stream)
{
    int ret = 0;
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fflush - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if(u_fflush(&ret, stream) != SGX_SUCCESS)
    {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}

void clearerr(FILE *stream)
{
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] clearerr - stream should be outside enclave\n");
        errno = EINVAL;
	return;
    }
    if(u_clearerr(stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }
    return;
}

int feof(FILE *stream)
{
    int ret = -1;
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] feof - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if(u_feof(&ret, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}

int ferror(FILE *stream)
{
    int ret = -1;
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] ferror - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if(u_ferror(&ret, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}

int fileno(FILE *stream)
{
    int ret = -1;
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] fileno - stream should be outside enclave\n");
        errno = EINVAL;
	return NULL;
    }
    if(u_fileno(&ret, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}

void rewind(FILE *stream)
{
    errno = 0;

    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] rewind - stream should be outside enclave\n");
        errno = EINVAL;
    }
    else if(u_rewind(stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
    }
    return;
}
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    ssize_t ret = 0;

    errno = 0;

    if((*lineptr == NULL && *n != 0) || (*lineptr != NULL && *n == 0))
    {
        SE_TRACE_ERROR("[stdc_ex] getline - invalid parameter\n");
        errno = EINVAL;
	return -1;
    }
    if(*lineptr && !sgx_is_outside_enclave(*lineptr, *n))
    {
        SE_TRACE_ERROR("[stdc_ex] getline - *lineptr should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] getline - stream should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(u_getline(&ret, lineptr, n, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    if(*lineptr && !sgx_is_outside_enclave(*lineptr, *n))
    {
        SE_TRACE_ERROR("[stdc_ex] getline - *lineptr should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    ssize_t ret = 0;

    errno = 0;

    if((*lineptr == NULL && *n != 0) || (*lineptr != NULL && *n == 0))
    {
        SE_TRACE_ERROR("[stdc_ex] getdelim - invalid parameter\n");
        errno = EINVAL;
	return -1;
    }
    if(*lineptr && !sgx_is_outside_enclave(*lineptr, *n))
    {
        SE_TRACE_ERROR("[stdc_ex] getdelim - *lineptr should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(!sgx_is_outside_enclave(stream, 1))
    {
        SE_TRACE_ERROR("[stdc_ex] getdelim - stream should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    if(u_getdelim(&ret, lineptr, n, delim, stream) != SGX_SUCCESS) {
        SE_TRACE_ERROR("[stdc_ex] OCALL failed\n");
        errno = EINVAL;
	return -1;
    }
    if(*lineptr && !sgx_is_outside_enclave(*lineptr, *n))
    {
        SE_TRACE_ERROR("[stdc_ex] getdelim - *lineptr should be outside enclave\n");
        errno = EINVAL;
	return -1;
    }
    return ret;
}
