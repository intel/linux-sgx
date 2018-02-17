//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information. 
//

/***
*   mbusafecrt.h - public declarations for SafeCRT lib
*

*
*   Purpose:
*       This file contains the public declarations SafeCRT
*       functions ported to MacOS. These are the safe versions of
*       functions standard functions banned by SWI
*

****/

/* shields! */

#ifndef MBUSAFECRT_H
#define MBUSAFECRT_H
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
typedef wchar_t WCHAR;

#ifdef __cplusplus
    extern "C" {
#endif

extern int strcat_s( char* ioDest, size_t inDestBufferSize, const char* inSrc );
extern int wcscat_s( WCHAR* ioDest, size_t inDestBufferSize, const WCHAR* inSrc );

extern int strncat_s( char* ioDest, size_t inDestBufferSize, const char* inSrc, size_t inCount );
extern int wcsncat_s( WCHAR* ioDest, size_t inDestBufferSize, const WCHAR* inSrc, size_t inCount );

extern int strcpy_s( char* outDest, size_t inDestBufferSize, const char* inSrc );
extern int wcscpy_s( WCHAR* outDest, size_t inDestBufferSize, const WCHAR* inSrc );

extern int strncpy_s( char* outDest, size_t inDestBufferSize, const char* inSrc, size_t inCount );
extern int wcsncpy_s( WCHAR* outDest, size_t inDestBufferSize, const WCHAR* inSrc, size_t inCount );

extern char* strtok_s( char* inString, const char* inControl, char** ioContext );
extern WCHAR* wcstok_s( WCHAR* inString, const WCHAR* inControl, WCHAR** ioContext );

extern size_t wcsnlen( const WCHAR* inString, size_t inMaxSize );

extern int _itoa_s( int inValue, char* outBuffer, size_t inDestBufferSize, int inRadix );
extern int _itow_s( int inValue, WCHAR* outBuffer, size_t inDestBufferSize, int inRadix );

extern int _ltoa_s( long inValue, char* outBuffer, size_t inDestBufferSize, int inRadix );
extern int _ltow_s( long inValue, WCHAR* outBuffer, size_t inDestBufferSize, int inRadix );

extern int _ultoa_s( unsigned long inValue, char* outBuffer, size_t inDestBufferSize, int inRadix );
extern int _ultow_s( unsigned long inValue, WCHAR* outBuffer, size_t inDestBufferSize, int inRadix );

extern int _i64toa_s( long long inValue, char* outBuffer, size_t inDestBufferSize, int inRadix );
extern int _i64tow_s( long long inValue, WCHAR* outBuffer, size_t inDestBufferSize, int inRadix );

extern int _ui64toa_s( unsigned long long inValue, char* outBuffer, size_t inDestBufferSize, int inRadix );
extern int _ui64tow_s( unsigned long long inValue, WCHAR* outBuffer, size_t inDestBufferSize, int inRadix );

extern int sprintf_s( char *string, size_t sizeInBytes, const char *format, ... );
extern int swprintf_s( WCHAR *string, size_t sizeInWords, const WCHAR *format, ... );

extern int _snprintf_s( char *string, size_t sizeInBytes, size_t count, const char *format, ... );
extern int _snwprintf_s( WCHAR *string, size_t sizeInWords, size_t count, const WCHAR *format, ... );

extern int _vsprintf_s( char* string, size_t sizeInBytes, const char* format, va_list arglist );
extern int _vsnprintf_s( char* string, size_t sizeInBytes, size_t count, const char* format, va_list arglist );

extern int _vswprintf_s( WCHAR* string, size_t sizeInWords, const WCHAR* format, va_list arglist );
extern int _vsnwprintf_s( WCHAR* string, size_t sizeInWords, size_t count, const WCHAR* format, va_list arglist );

extern int memcpy_s( void * dst, size_t sizeInBytes, const void * src, size_t count );
extern int memmove_s( void * dst, size_t sizeInBytes, const void * src, size_t count );

#ifdef __cplusplus
    }
#endif

#endif	/* MBUSAFECRT_H */
