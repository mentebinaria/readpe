####### Platform specifics

# cut is necessary for Cygwin
export PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Makefile Conventions - Directory variables

srcdir = .
prefix = /usr/local

exec_prefix = $(prefix)
sysconfdir = $(prefix)/etc
includedir = $(prefix)/include
datarootdir = $(prefix)/share
localstatedir = $(prefix)/var

bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
libexecdir = $(exec_prefix)/libexec
sbindir = $(exec_prefix)/sbin

datadir = $(datarootdir)
docdir = $(datarootdir)/doc/pev
infodir = $(datarootdir)/info
localedir = $(datarootdir)/locale

mandir = $(datarootdir)/man
manext = .1
man1dir = $(mandir)/man1
man1ext = .1

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

override LDFLAGS += -L$(LIBPE) -lpe -lcrypto -lssl -ldl -lm
override CFLAGS += -I$(LIBPE)/include -I"../include" -W -Wall -Wextra -std=c99 -pedantic
# Some gcc/clang builds (depends on the distro) already define _FORTIFY_SOURCE internally, so we
# undefine it first to avoid redefinition warnings.
override CPPFLAGS += \
	-D_GNU_SOURCE \
	-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1 \
	-DSHAREDIR="\"$(SHAREDIR)"\" \
	-DPLUGINSDIR="\"$(pluginsdir)"\"


ifeq ($(PLATFORM_OS), Darwin)
	# We disable warnings for deprecated declarations since Apple deprecated OpenSSL in Mac OS X 10.7
	override CFLAGS += -Wno-deprecated-declarations
endif

ifeq ($(PLATFORM_OS), CYGWIN)
	override CPPFLAGS += -D_XOPEN_SOURCE=600
endif

SRC_DIRS = $(srcdir) $(srcdir)/compat

PROGS = readpe rva2ofs ofs2rva pehash pesec pescan pepack pestr pedis peres peldd
PLUGINS_DIR = $(srcdir)/plugins
SHAREDIR = $(datadir)/pev
export LIBPE = $(realpath $(srcdir)/../lib/libpe)
LIBUDIS86 = $(srcdir)/../lib/libudis86
MANDIR = $(srcdir)/../doc/manpages

export pev_BUILDDIR = ./build
pev_SRCS_FILTER = $(wildcard ${dir}/*.c)
pev_SRCS = $(foreach dir, ${SRC_DIRS}, ${pev_SRCS_FILTER})
pev_OBJS = $(addprefix ${pev_BUILDDIR}/, $(addsuffix .o, $(basename ${pev_SRCS})))

pev_COMMON_DEPS = \
	$(pev_BUILDDIR)/compat/strlcat.o \
	$(pev_BUILDDIR)/config.o \
	$(pev_BUILDDIR)/dylib.o \
	$(pev_BUILDDIR)/malloc_s.o \
	$(pev_BUILDDIR)/plugins.o \
	$(pev_BUILDDIR)/output_plugin.o \
	$(pev_BUILDDIR)/output.o \
	$(pev_BUILDDIR)/pev_api.o

####### Build rules

.PHONY: plugins install installdirs uninstall clean

all: $(PROGS) plugins

plugins:
	cd $(PLUGINS_DIR) && $(MAKE) $@

ofs2rva: $(pev_BUILDDIR)/ofs2rva.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS)

pedis: CPPFLAGS += -DHAVE_STRING_H
pedis: CFLAGS += -I$(LIBUDIS86)
pedis: $(pev_BUILDDIR)/pedis.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS) $(LIBUDIS86)/libudis86/*.c

pehash: $(pev_BUILDDIR)/pehash.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

pepack: $(pev_BUILDDIR)/pepack.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

peres: $(pev_BUILDDIR)/peres.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

pescan: LDFLAGS += -lm
pescan: $(pev_BUILDDIR)/pescan.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

pesec: LDFLAGS += -lcrypto
pesec: $(pev_BUILDDIR)/pesec.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

pestr: $(pev_BUILDDIR)/pestr.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

readpe: $(pev_BUILDDIR)/readpe.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

rva2ofs: $(pev_BUILDDIR)/rva2ofs.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)
	
peldd: $(pev_BUILDDIR)/peldd.o $(pev_OBJS)
	$(CC) $< -o $(pev_BUILDDIR)/$@ $(pev_COMMON_DEPS) $(LDFLAGS) $(CFLAGS) $(CPPFLAGS)

# Generic rule matching sources

$(pev_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS) $(INCPATH)

install: installdirs
	for prog in $(PROGS); do \
		$(INSTALL_PROGRAM) $(INSTALL_FLAGS) $(pev_BUILDDIR)/$$prog $(DESTDIR)$(bindir); \
		$(CHK_FILE_EXISTS) $(MANDIR)/$$prog$(man1ext) && \
			gzip -c -9 $(MANDIR)/$$prog$(man1ext) > $(DESTDIR)$(man1dir)/$$prog$(man1ext).gz || \
			echo -n; \
	done

	$(INSTALL_DATA) $(srcdir)/userdb.txt $(DESTDIR)$(SHAREDIR)
	cd $(PLUGINS_DIR) && $(MAKE) $@

install-strip: INSTALL_FLAGS += -s
install-strip: install

installdirs:
	@$(CHK_DIR_EXISTS) $(DESTDIR) || $(MKDIR) $(DESTDIR)
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(bindir) || $(MKDIR) $(DESTDIR)$(bindir)
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(man1dir) || $(MKDIR) $(DESTDIR)$(man1dir)
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(SHAREDIR) || $(MKDIR) $(DESTDIR)$(SHAREDIR)

uninstall:
	for prog in $(PROGS); do \
		$(RM) $(DESTDIR)$(bindir)/$$prog; \
		$(RM) $(DESTDIR)$(man1dir)/$$prog$(man1ext).gz; \
	done
	$(RM_DIR) $(DESTDIR)$(SHAREDIR)
	cd $(PLUGINS_DIR) && $(MAKE) $@

clean:
	$(RM_DIR) $(pev_BUILDDIR)
	$(RM) $(PROGS)
	cd $(PLUGINS_DIR) && $(MAKE) $@
