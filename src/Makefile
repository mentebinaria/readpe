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

####### Build rules

# 'make' will compile all binaries
all: $(PROGS)

pestr: CPPFLAGS += -D_GNU_SOURCE=1
pestr: LDFLAGS += -lpcre
pestr: pestr.c

pehash: LDFLAGS += -lssl -lcrypto
pehash: pehash.c

pedis: CFLAGS += -I$(LIBUDIS86)
pedis: pedis.c $(LIBUDIS86)/libudis86/*.c

# Generic rule matching binary names and sources

%: %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $(SOURCES) $^ -o $@

install:
	test -d $(DEST) || mkdir -p $(DEST)
	for prog in $(PROGS); do \
		$(INSTALL) $$prog $(DEST); \
	done

uninstall:
	for prog in $(PROGS); do \
		$(RM) $(DEST)/$$prog; \
	done

clean:
	$(RM) $(PROGS)
