// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define STREAM_U convert_file_stream(stream)
static FILE *convert_file_stream(FILE *stream)
{
    if(stream == (FILE*)1) return stdin;
    else if (stream == (FILE*)2) return stdout;
    else if (stream == (FILE*)3) return stderr;
    else return stream;
}
int u_rename (const char *oldpath, const char *newpath)
{
    errno = 0;

    return rename(oldpath, newpath);
}
int u_remove(const char *pathname)
{
    errno = 0;

    return remove(pathname);
}

void u_fprintf(FILE *stream, const char* str, size_t maxlen)
{
    size_t len = strnlen(str, maxlen);
    fprintf(STREAM_U, "%.*s", (int)len, str);
    fflush(STREAM_U);
}
char *u_fgets(char *s, int size, FILE *stream)
{
    errno = 0;
    return fgets(s, size, STREAM_U);
}

FILE *u_fopen(const char *pathname, const char *mode)
{
    errno = 0;

    return fopen(pathname, mode);
}
FILE *u_fdopen(int fd, const char *mode)
{
    errno = 0;

    return fdopen(fd, mode);
}
int u_fclose(FILE *stream)
{
    errno = 0;

    return fclose(STREAM_U);
}

size_t u_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    errno = 0;

    return fread(ptr, size, nmemb, STREAM_U);
}

size_t u_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    errno = 0;

    return fwrite(ptr, size, nmemb, STREAM_U);
}

int u_fflush(FILE *stream)
{
    errno = 0;
    return fflush(STREAM_U);
}

void u_clearerr(FILE *stream)
{
    errno = 0;
    clearerr(STREAM_U);
}

int u_feof(FILE *stream)
{
    errno = 0;
    return feof(STREAM_U);
}

int u_ferror(FILE *stream)
{
    errno = 0;
    return ferror(STREAM_U);
}

int u_fileno(FILE *stream)
{
    errno = 0;
    return fileno(STREAM_U);
}

void u_rewind(FILE *stream)
{
    errno = 0;
    return rewind(STREAM_U);
}
ssize_t u_getline(char **lineptr, size_t *n, FILE *stream)
{
    errno = 0;
    return getline(lineptr, n, STREAM_U);
}

ssize_t u_getdelim(char **lineptr, size_t *n, int delim, FILE *stream)
{
    errno = 0;
    return getdelim(lineptr, n, delim, stream);
}

