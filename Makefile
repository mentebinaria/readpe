####### Platform specifics

# cut is necessary for Cygwin
PLATFORM_OS := $(shell uname | cut -d_ -f1)

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

override CFLAGS += \
	-O2 -ffast-math \
	-I"./include" \
	-fPIC \
	-W -Wall -Wextra -pedantic -std=c99 -c
override CPPFLAGS += -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
#override LDFLAGS += -lssl -lcrypto
LIBS = -lssl -lcrypto

# --- FIX: -fPIC is necessary to ALL shared objects! Changed above.
#ifneq ($(PLATFORM_OS), CYGWIN)
#	override CFLAGS += -fPIC
#endif

VERSION = 1.0
LIBNAME = libpe

SRC_DIRS = $(srcdir) $(srcdir)/libfuzzy $(srcdir)/libudis86

libpe_BUILDDIR = $(CURDIR)/build
libpe_SRCS_FILTER = $(wildcard ${dir}/*.c)
libpe_SRCS = $(foreach dir, ${SRC_DIRS}, ${libpe_SRCS_FILTER})
libpe_OBJS = $(addprefix ${libpe_BUILDDIR}/, $(addsuffix .o, $(basename ${libpe_SRCS})))

####### Build rules

.PHONY : libpe install strip-binaries install-strip uninstall clean

all: libpe

# FIX: WARNING.. ld expects -l option at the END of the command line or after the object files.
#      From gcc's documentation:
#
# It makes a difference where in the command you write this option; the linker searches and processes
# libraries and object files in the order they are specified. Thus, ‘foo.o -lz bar.o’ searches library
# ‘z’ after file foo.o but before bar.o. If bar.o refers to functions in ‘z’, those functions 
# may not be loaded.
#

libpe: CPPFLAGS += -D_GNU_SOURCE
ifeq ($(PLATFORM_OS), CYGWIN)
libpe: CPPFLAGS += -D_XOPEN_SOURCE=600
endif
libpe: $(libpe_OBJS)
ifeq ($(PLATFORM_OS), Linux)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $^ $(LIBS)
else ifeq ($(PLATFORM_OS), NetBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $^ $(LIBS)
else ifeq ($(PLATFORM_OS), FreeBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $^ $(LIBS)
else ifeq ($(PLATFORM_OS), OpenBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $^ $(LIBS)
else ifeq ($(PLATFORM_OS), Darwin)
	$(LINK) -headerpad_max_install_names -dynamiclib \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		$(LDFLAGS) -o $(LIBNAME).dylib $^ $(LIBS)
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(LINK) -shared -o $(LIBNAME).dll $^ $(LDFLAGS) $(LIBS)
endif

$(libpe_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

install: installdirs
ifeq ($(PLATFORM_OS), Linux)
	$(INSTALL_DATA) $(INSTALL_FLAGS) $(LIBNAME).so $(DESTDIR)$(libdir)/$(LIBNAME).so.$(VERSION)
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), NetBSD)
	$(INSTALL_DATA) $(INSTALL_FLAGS) $(LIBNAME).so $(DESTDIR)$(libdir)/$(LIBNAME).so.$(VERSION)
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), FreeBSD)
	$(INSTALL_DATA) $(INSTALL_FLAGS) $(LIBNAME).so $(DESTDIR)$(libdir)/$(LIBNAME).so.$(VERSION)
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), OpenBSD)
	$(INSTALL_DATA) $(INSTALL_FLAGS) $(LIBNAME).so $(DESTDIR)$(libdir)/$(LIBNAME).so.$(VERSION)
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), Darwin)
	$(INSTALL_DATA) $(INSTALL_FLAGS) $(LIBNAME).dylib $(DESTDIR)$(libdir)/$(LIBNAME).$(VERSION).dylib
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).dylib
	cd $(DESTDIR)$(libdir); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).1.dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	# TODO
endif

installdirs:
	@$(CHK_DIR_EXISTS) $(DESTDIR) || $(MKDIR) $(DESTDIR)
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(libdir) || $(MKDIR) $(DESTDIR)$(libdir)

install-strip: INSTALL_FLAGS += -s
install-strip: install

uninstall:
	$(RM) $(DESTDIR)$(libdir)/$(LIBNAME).so* \
		$(DESTDIR)$(libdir)/$(LIBNAME)*.dylib

clean:
	$(RM_DIR) $(libpe_BUILDDIR)
	$(RM) $(LIBNAME)*.o \
		$(LIBNAME)*.so \
		$(LIBNAME)*.dylib \
		$(LIBNAME)*.dll
