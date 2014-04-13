####### Compiler options

override CFLAGS += -I$(LIBPE) -I"../../include" -W -Wall -Wextra -std=c99 -pedantic -fpic
override CPPFLAGS += -D_GNU_SOURCE

PLUGINS = csv html text xml
VERSION = 1.0

plugins_BUILDDIR = ../$(pev_BUILDDIR)/plugins

csv_srcdir = $(CURDIR)
csv_SRCS = csv.c
csv_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${csv_SRCS})))
csv_LIBNAME = csv_plugin

html_srcdir = $(CURDIR)
html_SRCS = html.c
html_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${html_SRCS})))
html_LIBNAME = html_plugin

text_srcdir = $(CURDIR)
text_SRCS = text.c
text_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${text_SRCS})))
text_LIBNAME = text_plugin

xml_srcdir = $(CURDIR)
xml_SRCS = xml.c
xml_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${xml_SRCS})))
xml_LIBNAME = xml_plugin

####### Build rules

.PHONY: plugins

plugins: $(PLUGINS)

csv: LIBNAME = $(csv_LIBNAME)
csv: $(csv_OBJS)

html: LIBNAME = $(html_LIBNAME)
html: $(html_OBJS)

text: LIBNAME = $(text_LIBNAME)
text: $(text_OBJS)

xml: LIBNAME = $(xml_LIBNAME)
xml: $(xml_OBJS)

$(PLUGINS):
ifeq ($(PLATFORM_OS), Linux)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o ${plugins_BUILDDIR}/$(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), Darwin)
	$(LINK) -headerpad_max_install_names -dynamiclib \
		-undefined suppress -fno-common \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		$(LDFLAGS) -o ${plugins_BUILDDIR}/$(LIBNAME).dylib $^
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(LINK) -shared $(LDFLAGS) -o ${plugins_BUILDDIR}/$(LIBNAME).dll $^
endif

$(plugins_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $^

clean:
	$(RM_DIR) ${plugins_BUILDDIR}

###

install:
	$(INSTALL_PROGRAM) -m 755 $(plugins_BUILDDIR)/$(csv_LIBNAME).* $(pluginsdir)
	$(INSTALL_PROGRAM) -m 755 $(plugins_BUILDDIR)/$(html_LIBNAME).* $(pluginsdir)
	$(INSTALL_PROGRAM) -m 755 $(plugins_BUILDDIR)/$(text_LIBNAME).* $(pluginsdir)
	$(INSTALL_PROGRAM) -m 755 $(plugins_BUILDDIR)/$(xml_LIBNAME).* $(pluginsdir)

uninstall:
	$(RM) $(pluginsdir)/*
