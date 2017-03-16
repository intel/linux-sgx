#!/usr/bin/make -f

GTEST_INCLUDE_DIR = ..
GTEST_SRC = $(wildcard ./*.cc)
GTEST_OBJ = $(GTEST_SRC:.cc=.o)

GTEST_LIB = libgtest.a

CXXFLAGS += -DGTEST_HAS_PTHREAD=0

$(GTEST_OBJ): %.o: %.cc
	$(CXX) -o $@ -c $(CXXFLAGS) -I$(GTEST_INCLUDE_DIR) $<

$(GTEST_LIB): $(GTEST_OBJ)
	$(AR) rc $@ $^
	ranlib $@

build: all

all: $(GTEST_LIB)

install:

clean:
	rm -f $(GTEST_OBJ) $(GTEST_LIB)
