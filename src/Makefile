####### Platform specifics

# cut is necessary for Cygwin
PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Makefile Conventions - Directory variables

prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin
libexecdir = $(exec_prefix)/libexec
datarootdir = $(prefix)/share
datadir = $(datarootdir)
sysconfdir = $(prefix)/etc
localstatedir = $(prefix)/var
includedir = $(prefix)/include
docdir = $(datarootdir)/doc/pev
infodir = $(datarootdir)/info
libdir = $(exec_prefix)/lib
localedir = $(datarootdir)/locale
mandir = $(datarootdir)/man
man1dir = $(mandir)/man1
manext = .1
man1ext = .1
srcdir = $(CURDIR)

####### Makefile Conventions - Utilities

CC ?= gcc
LINK = $(CC)
CHK_DIR_EXISTS = test -d
CHK_FILE_EXISTS = test -f
INSTALL = install
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PROGRAM = $(INSTALL)
SYMLINK = ln -sf
MKDIR = mkdir -p
RM = rm -f
RM_DIR = rm -rf
ifeq ($(PLATFORM_OS), Darwin)
	STRIP = strip -x
else
	STRIP = strip --strip-unneeded
endif

####### Compiler options

DEST = $(DESTDIR)$(bindir)
override LDFLAGS += -L$(LIBPE) -lpe
override CFLAGS += -I$(LIBPE) -W -Wall -Wextra -std=c99 -pedantic
ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations since Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS += -Wno-deprecated-declarations
endif

PROGS = readpe rva2ofs ofs2rva pehash pesec pescan pepack pestr # pedis peres
SHAREDIR = $(datadir)/pev
LIBPE = $(srcdir)/../lib/libpe
LIBUDIS86 = $(srcdir)/../lib/libudis86
MANDIR = $(srcdir)/../doc/manpages

####### Build rules

.PHONY : install uninstall clean

all: $(PROGS)

pesec: LDFLAGS += -lcrypto
pesec: compat/strlcat.c

pestr: CPPFLAGS += -D_GNU_SOURCE
pestr: LDFLAGS += -lpcre

pehash: LDFLAGS += -lssl -lcrypto

pedis: CFLAGS += -I$(LIBUDIS86)
pedis: $(LIBUDIS86)/libudis86/*.c

pescan: LDFLAGS += -lm

# Generic rule matching binary names and sources

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) output.c xmalloc.c $^ -o $@ $(LDFLAGS)

install: installdirs
	for prog in $(PROGS); do \
		$(INSTALL_PROGRAM) -m 755 $$prog $(DEST); \
		$(CHK_FILE_EXISTS) $(MANDIR)/$$prog$(man1ext) && \
			gzip -c -9 $(MANDIR)/$$prog$(man1ext) > $(man1dir)/$$prog$(man1ext).gz || \
			echo -n; \
	done
	# TODO: Should we copy it anyway if it already exists?
	@$(CHK_FILE_EXISTS) $(SHAREDIR)/userdb.txt || cp $(srcdir)/userdb.txt $(SHAREDIR)

installdirs:
	@$(CHK_DIR_EXISTS) $(DEST) || $(MKDIR) $(DEST)
	@$(CHK_DIR_EXISTS) $(man1dir) || $(MKDIR) $(man1dir)
	@$(CHK_DIR_EXISTS) $(SHAREDIR) || $(MKDIR) $(SHAREDIR)

uninstall:
	for prog in $(PROGS); do \
		$(RM) $(DEST)/$$prog; \
		$(RM) $(man1dir)/$$prog$(man1ext).gz; \
	done

clean:
	$(RM) $(PROGS)
