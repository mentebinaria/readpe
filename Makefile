####### Platform specifics

# cut is necessary for Cygwin
PLATFORM_OS := $(shell uname | cut -d_ -f1)

####### Makefile Conventions - Directory variables

prefix = /usr
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
sbindir = $(exec_prefix)/sbin
libexecdir = $(exec_prefix)/libexec
datarootdir = $(prefix)/share
datadir = $(datarootdir)
sysconfdir = $(prefix)/etc
localstatedir = $(prefix)/var
includedir = $(prefix)/include
docdir = $(datarootdir)/doc/libpe
infodir = $(datarootdir)/info
libdir = $(exec_prefix)/lib
localedir = $(datarootdir)/locale
mandir = $(datarootdir)/man
man1dir = $(mandir)/man1
manext = .1
man1ext = .1
srcdir = .

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

DEST = $(DESTDIR)$(libdir)
override CFLAGS += -W -Wall -Wextra -pedantic -std=c99 -c
ifneq ($(PLATFORM_OS), CYGWIN)
	override CFLAGS += -fPIC
endif

VERSION = 1.0
LIBNAME = libpe

libpe_BUILDDIR = $(CURDIR)/build
libpe_SRCS_FILTER = $(wildcard ${dir}/*.c)
libpe_SRCS = $(foreach dir, ${srcdir}, ${libpe_SRCS_FILTER})
libpe_OBJS = $(addprefix ${libpe_BUILDDIR}/, $(addsuffix .o, $(basename ${libpe_SRCS})))

####### Build rules

.PHONY : libpe install strip-binaries install-strip uninstall clean

all: libpe

libpe: CPPFLAGS += -D_GNU_SOURCE
ifeq ($(PLATFORM_OS), CYGWIN)
libpe: CPPFLAGS += -D_XOPEN_SOURCE=500
endif
libpe: $(libpe_OBJS)
ifeq ($(PLATFORM_OS), Linux)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), Darwin)
	$(LINK) -headerpad_max_install_names -dynamiclib \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		$(LDFLAGS) -o $(LIBNAME).dylib $^
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(LINK) -shared $(LDFLAGS) -o $(LIBNAME).dll $^
endif

$(libpe_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

install: installdirs
ifeq ($(PLATFORM_OS), Linux)
	$(INSTALL_DATA) $(LIBNAME).so $(DEST)/$(LIBNAME).so.$(VERSION)
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so
	cd $(DEST); $(SYMLINK) $(LIBNAME).so.$(VERSION) $(LIBNAME).so.1
else ifeq ($(PLATFORM_OS), Darwin)
	$(INSTALL_DATA) $(LIBNAME).dylib $(DEST)/$(LIBNAME).$(VERSION).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).dylib
	cd $(DEST); $(SYMLINK) $(LIBNAME).$(VERSION).dylib $(LIBNAME).1.dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	# TODO
endif

installdirs:
	@$(CHK_DIR_EXISTS) $(DEST) || $(MKDIR) $(DEST)

strip-binaries:
ifeq ($(PLATFORM_OS), Linux)
	$(STRIP) $(LIBNAME).so
else ifeq ($(PLATFORM_OS), Darwin)
	$(STRIP) $(LIBNAME).dylib
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(STRIP) $(LIBNAME).dll
endif

install-strip: strip-binaries install

uninstall:
	$(RM) $(DEST)/$(LIBNAME).so* \
		$(DEST)/$(LIBNAME)*.dylib

clean:
	$(RM_DIR) $(libpe_BUILDDIR)
	$(RM) $(LIBNAME)*.o \
		$(LIBNAME)*.so \
		$(LIBNAME)*.dylib \
		$(LIBNAME)*.dll
