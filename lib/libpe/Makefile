####### Platform specifics

PLATFORM_OS := $(shell uname)

####### Compiler, tools and options

PREFIX=/usr
DEST=$(DESTDIR)/$(PREFIX)/lib
VERSION=1.0
CFLAGS=-W -Wall -Wextra -pedantic -std=c99
SRC=pe.c
RM=rm -f
CC=gcc
SYMLINK=ln -sf
STRIP=strip --strip-unneeded
LIBNAME=libpe
INSTALL=install -m 0644

####### Build rules

all: pe.c pe.h
	$(CC) -o $(LIBNAME).o -c $(CFLAGS) -fPIC $(SRC)
ifeq ($(PLATFORM_OS), Linux)
	$(CC) -shared -Wl,-soname,$(LIBNAME).so.1 -o $(LIBNAME).so $(LIBNAME).o
else ifeq ($(PLATFORM_OS), Darwin)
	$(CC) -headerpad_max_install_names -dynamiclib \
		-flat_namespace -install_name $(TARGET).$(TARGET_VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		-o $(LIBNAME).dylib $(LIBNAME).o
endif

install:
	$(STRIP) $(LIBNAME).so
	test -d $(DEST) || mkdir -p $(DEST)
ifeq ($(PLATFORM_OS), Linux)
	$(INSTALL) $(LIBNAME).so $(DEST)/$(LIBNAME).so.$(VERSION)
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), Darwin)
	$(INSTALL) $(LIBNAME).dylib $(DEST)/$(LIBNAME).$(VERSION).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).1.dylib
endif

uninstall:
	$(RM) $(DEST)/$(LIBNAME).so* \
		$(DEST)/$(LIBNAME)*.dylib

clean:
	$(RM) $(LIBNAME).*o* \
		$(LIBNAME).so* \
		$(LIBNAME)*.dylib
