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
srcdir = .
sysconfdir = $(prefix)/etc
export pluginsdir = $(libdir)/pev/plugins

####### Makefile Conventions - Utilities

export CC ?= gcc
export LINK = $(CC)
export CHK_DIR_EXISTS = test -d
export CHK_FILE_EXISTS = test -f
export INSTALL = install
export INSTALL_DATA = ${INSTALL} -m 644
export INSTALL_PROGRAM = ${INSTALL}
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
override CFLAGS += -I$(LIBPE) -I"../include" -W -Wall -Wextra -std=c99 -pedantic -fPIC
override CPPFLAGS += -D_GNU_SOURCE
ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations since Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS += -Wno-deprecated-declarations
endif

SRC_DIRS = $(srcdir) $(srcdir)/compat $(srcdir)/../lib/libfuzzy

PROGS = readpe rva2ofs ofs2rva pehash pesec pescan pepack pestr pedis peres
PLUGINS_DIR = $(srcdir)/plugins
SHAREDIR = $(datadir)/pev
export LIBPE = $(srcdir)/../lib/libpe
LIBUDIS86 = $(srcdir)/../lib/libudis86
LIBFUZZY = $(srcdir)/../lib/libfuzzy
MANDIR = $(srcdir)/../doc/manpages

export pev_BUILDDIR = ./build
pev_SRCS_FILTER = $(wildcard ${dir}/*.c)
pev_SRCS = $(foreach dir, ${SRC_DIRS}, ${pev_SRCS_FILTER})
pev_OBJS = $(addprefix ${pev_BUILDDIR}/, $(addsuffix .o, $(basename ${pev_SRCS})))

export pev_COMMON_DEPS = \
	$(pev_BUILDDIR)/compat/strlcat.o \
	$(pev_BUILDDIR)/config.o \
	$(pev_BUILDDIR)/dylib.o \
	$(pev_BUILDDIR)/malloc_s.o \
	$(pev_BUILDDIR)/utils.o \
	$(pev_BUILDDIR)/plugins.o \
	$(pev_BUILDDIR)/output_plugin.o \
	$(pev_BUILDDIR)/output.o

####### Build rules

.PHONY: plugins install installdirs uninstall clean

all: $(PROGS) plugins

plugins:
	cd $(PLUGINS_DIR) && $(MAKE) $@

ofs2rva: $(pev_BUILDDIR)/ofs2rva.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

pedis: CFLAGS += -I$(LIBUDIS86)
pedis: $(LIBUDIS86)/libudis86/*.c
pedis: $(pev_BUILDDIR)/pedis.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) $(LIBUDIS86)/libudis86/*.c

pehash: LDFLAGS += -lssl -lcrypto
pehash: CFLAGS += -I$(LIBFUZZY)
pehash: $(pev_BUILDDIR)/pehash.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) $(LIBFUZZY)/*.c

pepack: $(pev_BUILDDIR)/pepack.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

peres: $(pev_BUILDDIR)/peres.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

pescan: LDFLAGS += -lm
pescan: $(pev_BUILDDIR)/pescan.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

pesec: LDFLAGS += -lcrypto
pesec: $(pev_BUILDDIR)/pesec.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

pestr: $(pev_BUILDDIR)/pestr.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

readpe: $(pev_BUILDDIR)/readpe.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

rva2ofs: $(pev_BUILDDIR)/rva2ofs.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

# Generic rule matching sources

$(pev_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(INCPATH)

install: installdirs
	for prog in $(PROGS); do \
		$(INSTALL_PROGRAM) $(pev_BUILDDIR)/$$prog $(DEST); \
		$(CHK_FILE_EXISTS) $(MANDIR)/$$prog$(man1ext) && \
			gzip -c -9 $(MANDIR)/$$prog$(man1ext) > $(man1dir)/$$prog$(man1ext).gz || \
			echo -n; \
	done

	$(INSTALL_DATA) $(srcdir)/userdb.txt $(SHAREDIR)
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
	$(RM_DIR) $(pev_BUILDDIR)
	$(RM) $(PROGS)
	cd $(PLUGINS_DIR) && $(MAKE) $@