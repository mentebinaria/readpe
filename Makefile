CC=gcc
SRC=pev.c
CFLAGS=-O2 -Wall -ansi

all: pev

install:
	install pev $(DESTDIR)/usr/bin
	gzip -c -9 pev.1 > $(DESTDIR)/usr/share/man/man1/pev.1.gz

clean:
	rm -f pev pev.o

uninstall:
	rm -f $(DESTDIR)/usr/bin/pev
	rm -f $(DESTDIR)/usr/share/man/man1/pev.1.gz
