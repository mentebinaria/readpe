####### Platform specifics

# cut is necessary for Cygwin
export PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Makefile Conventions - Directory variables

bindir = $(exec_prefix)/bin
datadir = $(datarootdir)
datarootdir = $(prefix)/share
docdir = $(datarootdir)/doc/pev
exec_prefix = $(prefix)
includedir = $(prefix)/include
infodir = $(datarootdir)/info
libdir = $(exec_prefix)/lib
libexecdir = $(exec_prefix)/libexec
localedir = $(datarootdir)/locale
localstatedir = $(prefix)/var
man1dir = $(mandir)/man1
man1ext = .1
mandir = $(datarootdir)/man
manext = .1
prefix = /usr
sbindir = $(exec_prefix)/sbin
srcdir = $(CURDIR)
sysconfdir = $(prefix)/etc
export pluginsdir = $(libdir)/pev/plugins

####### Makefile Conventions - Utilities

export CC ?= gcc
export LINK = $(CC)
export CHK_DIR_EXISTS = test -d
export CHK_FILE_EXISTS = test -f
export INSTALL = install
export INSTALL_DATA = ${INSTALL} -m 644
export INSTALL_PROGRAM = $(INSTALL)
export SYMLINK = ln -sf
export MKDIR = mkdir -p
export RM = rm -f
export RM_DIR = rm -rf
ifeq ($(PLATFORM_OS), Darwin)
	export STRIP = strip -x
else
	export STRIP = strip --strip-unneeded
endif

####### Compiler options

export DEST = $(DESTDIR)$(bindir)

override LDFLAGS += -L$(LIBPE) -rdynamic -lpe -ldl
override CFLAGS += -I$(LIBPE) -I"../include" -W -Wall -Wextra -std=c99 -pedantic
override CPPFLAGS += -D_GNU_SOURCE
ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations since Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS += -Wno-deprecated-declarations
endif

PROGS = readpe rva2ofs ofs2rva pehash pesec pescan pepack pestr pedis peres
PLUGINS_DIR = $(srcdir)/plugins
SHAREDIR = $(datadir)/pev
export LIBPE = $(srcdir)/../lib/libpe
LIBUDIS86 = $(srcdir)/../lib/libudis86
LIBFUZZY = $(srcdir)/../lib/libfuzzy
MANDIR = $(srcdir)/../doc/manpages

####### Build rules

.PHONY: plugins install installdirs uninstall clean

all: $(PROGS) plugins

plugins:
	cd $(PLUGINS_DIR) && $(MAKE) $@

pesec: LDFLAGS += -lcrypto

pehash: CFLAGS += -I$(LIBFUZZY)
pehash: $(LIBFUZZY)/*.c
pehash: LDFLAGS += -lssl -lcrypto

pedis: CFLAGS += -I$(LIBUDIS86)
pedis: $(LIBUDIS86)/libudis86/*.c

pescan: LDFLAGS += -lm

# Generic rule matching binary names and sources

%: %.c
	@# NOTE: The order of translation units here is EXTREMELY IMPORTANT.
	@#       If you're compiling with gcc, you don't have to worry, but other
	@#		compilers like clang (default on Mac OS X) do not respect the
	@#		priorities defined in `__attribute__((constructor (priority)))`.
	$(CC) $(CFLAGS) $(CPPFLAGS) \
		compat/strlcat.c \
		config.c \
		dylib.c \
		malloc_s.c \
		plugins.c \
		output_plugin.c \
		output.c \
		$^ -o $@ $(LDFLAGS)

install: installdirs
	for prog in $(PROGS); do \
		$(INSTALL_PROGRAM) -m 755 $$prog $(DEST); \
		$(CHK_FILE_EXISTS) $(MANDIR)/$$prog$(man1ext) && \
			gzip -c -9 $(MANDIR)/$$prog$(man1ext) > $(man1dir)/$$prog$(man1ext).gz || \
			echo -n; \
	done
	# TODO: Should we copy it anyway if it already exists?
	@$(CHK_FILE_EXISTS) $(SHAREDIR)/userdb.txt || cp $(srcdir)/userdb.txt $(SHAREDIR)
	cd $(PLUGINS_DIR) && $(MAKE) $@

installdirs:
	@$(CHK_DIR_EXISTS) $(DEST) || $(MKDIR) $(DEST)
	@$(CHK_DIR_EXISTS) $(man1dir) || $(MKDIR) $(man1dir)
	@$(CHK_DIR_EXISTS) $(SHAREDIR) || $(MKDIR) $(SHAREDIR)
	@$(CHK_DIR_EXISTS) $(pluginsdir) || $(MKDIR) $(pluginsdir)

uninstall:
	for prog in $(PROGS); do \
		$(RM) $(DEST)/$$prog; \
		$(RM) $(man1dir)/$$prog$(man1ext).gz; \
	done
	cd $(PLUGINS_DIR) && $(MAKE) $@

clean:
	$(RM) $(PROGS)
	cd $(PLUGINS_DIR) && $(MAKE) $@
