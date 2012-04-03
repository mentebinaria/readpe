CC=gcc
SRC=$(wildcard src/*.c)
WARNS=-W -Wall -Wextra -pedantic
CFLAGS=$(WARNS) -std=c99
DFLAGS=-D __DEBUG_MODE__

all:
	$(CC) $(CFLAGS) $(DFLAGS) -o pev $(SRC)

install:
	install pev $(DESTDIR)/usr/bin
	gzip -c -9 pev.1 > $(DESTDIR)/usr/share/man/man1/pev.1.gz

clean:
	rm -f pev

uninstall:
	rm -f $(DESTDIR)/usr/bin/pev
	rm -f $(DESTDIR)/usr/share/man/man1/pev.1.gz
