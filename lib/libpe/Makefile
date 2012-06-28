PREFIX=/usr
DEST=$(DESTDIR)/$(PREFIX)/lib
VERSION=1.0
CFLAGS=-W -Wall -Wextra -pedantic -std=c99
SRC=pe.c
RM=rm -f
CC=gcc
LN=ln -sf
STRIP=strip --strip-unneeded
LIBNAME=libpe
INSTALL=install -m 0644

all: pe.c pe.h
	$(CC) -o $(LIBNAME).o -c $(CFLAGS) -fPIC $(SRC)
	$(CC) -shared -Wl,-soname,$(LIBNAME).so.1 -o $(LIBNAME).so $(LIBNAME).o

install:
	$(STRIP) $(LIBNAME).so
	test -d $(DEST) || mkdir -p $(DEST)
	$(INSTALL) $(LIBNAME).so $(DEST)/$(LIBNAME).so.$(VERSION)
	cd $(DEST); $(LN) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DEST); $(LN) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1

uninstall:
	$(RM) $(DEST)/$(LIBNAME).so*

clean:
	$(RM) $(LIBNAME).*o*
