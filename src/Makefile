LIBPE=../lib/libpe
LIBUDIS86=../lib/libudis86
CFLAGS=-W -Wall -Wextra -std=c99 -pedantic
CC=gcc
RM=rm -f
COMMON=output.c
PROGS=readpe pedis packid petls rva2ofs pesec

# 'make' only will compile all binaries
all: $(PROGS)

# special rule to include libudis86
pedis: pedis.c
	$(CC) $(CFLAGS) -I$(LIBPE) -L$(LIBPE) -I$(LIBUDIS86) $(LIBUDIS86)/libudis86/*.c $^ $(COMMON) -o $@ -lpe

# general rule match binary name and source
%: %.c
	$(CC) $(CFLAGS) -I$(LIBPE) -L$(LIBPE) $^ $(COMMON) -o $@ -lpe

# remove compiled binaries
clean:
	$(RM) $(PROGS)
