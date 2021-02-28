####### Compiler options

override CFLAGS += -I$(LIBPE) -I"../../include" -W -Wall -Wextra -std=c99 -pedantic -fPIC
override CPPFLAGS += -D_GNU_SOURCE

PLUGINS = csv html text xml json yarascan
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

json_srcdir = $(CURDIR)
json_SRCS = json.c
json_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${json_SRCS})))
json_LIBNAME = json_plugin

yarascan_srcdir = $(CURDIR)
yarascan_SRCS = yarascan.c
yarascan_OBJS = $(addprefix ${plugins_BUILDDIR}/, $(addsuffix .o, $(basename ${yarascan_SRCS})))
yarascan_LIBNAME = yarascan
yarascan_plugin_dir=$(PLUGIN_CONFIG_DIR)/yara_rules/

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

json: LIBNAME = $(json_LIBNAME)
json: $(json_OBJS)

yarascan: LIBNAME = $(yarascan_LIBNAME)
yarascan: DEPS=-lyara
yarascan: CPLUGIN_FLAGS=-DYARA_RULES_DIR="\"$(yarascan_plugin_dir)\""
yarascan: $(yarascan_OBJS)

$(PLUGINS):
ifeq ($(PLATFORM_OS), Linux)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) $(DEPS) -o ${plugins_BUILDDIR}/$(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), NetBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) $(DEPS) -o ${plugins_BUILDDIR}/$(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), FreeBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) $(DEPS) -o ${plugins_BUILDDIR}/$(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), OpenBSD)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) $(DEPS) -o ${plugins_BUILDDIR}/$(LIBNAME).so $^
else ifeq ($(PLATFORM_OS), Darwin)
	$(LINK) -headerpad_max_install_names -dynamiclib \
		-undefined dynamic_lookup -fno-common \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		$(LDFLAGS) -o ${plugins_BUILDDIR}/$(LIBNAME).dylib $^
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(LINK) -shared $(LDFLAGS) -o ${plugins_BUILDDIR}/$(LIBNAME).dll $^
endif

$(plugins_BUILDDIR)/%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(CPLUGIN_FLAGS) -o $@ $^

clean:
	$(RM_DIR) ${plugins_BUILDDIR}

###

install: installdirs
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(csv_LIBNAME).* $(DESTDIR)$(pluginsdir)
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(html_LIBNAME).* $(DESTDIR)$(pluginsdir)
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(text_LIBNAME).* $(DESTDIR)$(pluginsdir)
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(xml_LIBNAME).* $(DESTDIR)$(pluginsdir)
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(json_LIBNAME).* $(DESTDIR)$(pluginsdir)
	$(INSTALL_PROGRAM) $(INSTALL_FLAGS) -m 755 $(plugins_BUILDDIR)/$(yarascan_LIBNAME).* $(DESTDIR)$(pluginsdir)

install-strip: INSTALL_FLAGS += -s
install-strip: install

installdirs:
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(pluginsdir) || $(MKDIR) $(DESTDIR)$(pluginsdir)
	@$(CHK_DIR_EXISTS) $(DESTDIR)$(yarascan_plugin_dir) || $(MKDIR) $(DESTDIR)$(yarascan_plugin_dir)


uninstall:
	$(RM_DIR) $(DESTDIR)$(pluginsdir)
