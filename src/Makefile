PREFIX=/usr
DEST=$(DESTDIR)/$(PREFIX)/bin
LIBPE=../lib/libpe
LIBUDIS86=../lib/libudis86
CFLAGS=-W -Wall -Wextra -std=c99 -pedantic
CC=gcc
RM=rm -f
COMMON=output.c
PROGS=readpe pedis pepack pescan rva2ofs pesec ofs2rva pestr pehash
INSTALL=install -m 0755

# 'make' only will compile all binaries
all: $(PROGS)

# include libssl
pehash: pehash.c
	$(CC) $(CFLAGS) -I$(LIBPE) -L$(LIBPE) $^ $(COMMON) -o $@ -lpe -lssl -lcrypto

# include libudis86
pedis: pedis.c
	$(CC) $(CFLAGS) -I$(LIBPE) -L$(LIBPE) -I$(LIBUDIS86) $(LIBUDIS86)/libudis86/*.c $^ $(COMMON) -o $@ -lpe

# generic rule matching binary names and sources
%: %.c
	$(CC) $(CFLAGS) -I$(LIBPE) -L$(LIBPE) $^ $(COMMON) -o $@ -lpe

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
