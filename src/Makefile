####### Platform specifics

# cut is necessary for Cygwin
PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Compiler, tools and options

PREFIX = /usr
DEST = $(DESTDIR)/$(PREFIX)/bin
LIBPE = ../lib/libpe
LIBUDIS86 = ../lib/libudis86
override LDFLAGS += -L$(LIBPE) -lpe
override CFLAGS += -I$(LIBPE) -W -Wall -Wextra -std=c99 -pedantic
ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations since Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS += -Wno-deprecated-declarations
endif
CC = gcc
RM = rm -f
SOURCES = output.c
PROGS = readpe pedis pepack pescan rva2ofs pesec ofs2rva pestr pehash pestr
INSTALL = install -m 0755
SHAREDIR = /usr/share/pev
MAN = ../doc/manpages
MANDIR = /usr/share/man/man1

####### Build rules

# 'make' will compile all binaries
all: $(PROGS)

pesec: LDFLAGS += -lcrypto

pestr: CPPFLAGS += -D_GNU_SOURCE=1
pestr: LDFLAGS += -lpcre
pestr: pestr.c

pehash: LDFLAGS += -lssl -lcrypto
pehash: pehash.c

pedis: CFLAGS += -I$(LIBUDIS86)
pedis: pedis.c $(LIBUDIS86)/libudis86/*.c

pescan: LDFLAGS += -lm

# Generic rule matching binary names and sources

%: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SOURCES) $^ -o $@ $(LDFLAGS)

install:
	test -d $(DEST) || mkdir -p $(DEST)
	for prog in $(PROGS); do \
		$(INSTALL) $$prog $(DEST); \
		test -f $(MAN)/$$prog.1 && gzip -c -9 $(MAN)/$$prog.1 > $(MANDIR)/$$prog.1.gz || echo -n; \
	done
	test -d $(SHAREDIR) || mkdir -p $(SHAREDIR)
	test -f $(SHAREDIR)/userdb.txt || cp userdb.txt $(SHAREDIR)

uninstall:
	for prog in $(PROGS); do \
		$(RM) $(DEST)/$$prog; \
		$(RM) $(MANDIR)/$$prog.1.gz; \
	done

clean:
	$(RM) $(PROGS)
