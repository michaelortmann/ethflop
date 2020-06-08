#
# ethflopd makefile for Linux
# http://ethflop.sourceforge.net
#
# Copyright (C) 2019 Mateusz Viste
# Copyright (c) 2020 Michael Ortmann
#
# make        - builds ethflopd (Linux daemon)
# make tsr    - builds ethflop.com (DOS TSR, requires NASM)
# make test   - builds the test app (requires tcc 2.01)
#

# for debug
#CC = clang
#CFLAGS = -O2 -Wall -std=gnu89 -pedantic -Wextra -Wformat-security -D_FORTIFY_SOURCE=1 -Weverything -Wno-padded

# production
CC ?= gcc
CFLAGS := -O2 -std=gnu89 -Wall $(CFLAGS)

all: ethflopd

ethflopd: ethflopd.c

tsr:
	nasm -f bin -l ethflop.lst -o ethflop.com ethflop.asm

test: test.c
	tcc -f- -ms -w -N test.c

pkg: tsr
	rm -f ethflop-*.zip
	zip -9 -K ethflop-`date +%Y%m%d`.zip ethflop.com ethflop.asm ethflop.txt history.txt Makefile ethflopd.c

clean:
	rm -f ethflopd ethflop.com *.o *.zip *.lst
