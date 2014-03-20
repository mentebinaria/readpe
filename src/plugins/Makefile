####### Compiler options

override LDFLAGS += 
override CFLAGS += -I$(LIBPE) -I"../../include" -W -Wall -Wextra -std=c99 -pedantic -fpic
override CPPFLAGS += -D_GNU_SOURCE

PLUGINS = csv html text xml
VERSION = 1.0

####### Build rules

.PHONY:

plugins: $(PLUGINS)

csv_plugin: csv.o
csv_plugin: LIBNAME = $@
csv: csv.o csv_plugin
	@#echo

html_plugin: html.o
html_plugin: LIBNAME = $@
html: html.o html_plugin
	@#echo

text_plugin: text.o
text_plugin: LIBNAME = $@
text: text.o text_plugin
	@#echo

xml_plugin: xml.o
xml_plugin: LIBNAME = $@
xml: xml.o xml_plugin
	@#echo

%_plugin:
ifeq ($(PLATFORM_OS), Linux)
	$(LINK) -shared -Wl,-soname,$(LIBNAME).so.1 $(LDFLAGS) -o $(LIBNAME).so $<
else ifeq ($(PLATFORM_OS), Darwin)
	$(LINK) -headerpad_max_install_names -dynamiclib \
		-undefined suppress -fno-common \
		-flat_namespace -install_name $(LIBNAME).$(VERSION).dylib \
		-current_version $(VERSION) -compatibility_version $(VERSION) \
		$(LDFLAGS) -o $(LIBNAME).dylib $^
else ifeq ($(PLATFORM_OS), CYGWIN)
	$(LINK) -shared $(LDFLAGS) -o $(LIBNAME).dll $^
endif

%.o: %.c
	@$(CHK_DIR_EXISTS) $(dir $@) || $(MKDIR) $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

clean:
	$(RM) *.o \
		*.so \
		*.dylib \
		*.dll
