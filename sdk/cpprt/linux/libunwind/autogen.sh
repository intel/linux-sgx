#!/bin/sh

test -n "$srcdir" || srcdir=`dirname "$0"`
test -n "$srcdir" || srcdir=.
(
  cd "$srcdir" &&
  autoreconf --force -v --install
) || exit

#CFLAGS="$CFLAGS -g -O0 -std=c99 -fno-builtin -DHAVE_SGX=1 -fPIC -DUNW_LOCAL_ONLY"
if [ "$1" = "1" ] 
then
    #Build with "make DEBUG=1"
    COMMON_FLAGS="-ggdb -Og"
else
    COMMON_FLAGS="-g -O2"
fi
CFLAGS="$COMMON_FLAGS -std=c99 -fno-builtin -DHAVE_SGX=1 -fPIC -DUNW_LOCAL_ONLY -fdebug-prefix-map=$(pwd)=/libunwind"

# Remove duplicated compiler options and filter out `-nostdinc'
CFLAGS=`echo $CFLAGS | tr ' ' '\n' | grep -v nostdinc | tr '\n' ' '`

export CFLAGS
test -n "$NOCONFIGURE" || "$srcdir/configure" --enable-shared=no \
                                              --disable-block-signals \
                                              --enable-debug=no \
                                              --enable-debug-frame=no \
                                              --enable-coredump=no \
                                              --enable-ptrace=no \
                                              --enable-setjmp=no \
                                              --disable-tests    \
                                              --enable-cxx-exceptions

#Remove the HAVE_MINCORE because inside SGX doesn't exist mincore() function
sed -i 's/#define HAVE_MINCORE/\/\/#define HAVE_MINCORE/g' include/config.h
