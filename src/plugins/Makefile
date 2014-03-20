
####### Compiler options

override LDFLAGS += 
override CFLAGS += -I$(LIBPE) -I"../../include" -W -Wall -Wextra -std=c99 -pedantic -fpic
override CPPFLAGS += -D_GNU_SOURCE

PLUGINS = csv html text xml
VERSION = 1.0

####### Build rules

.PHONY: %.lib

CFLAGS += -fPIC

plugins: $(PLUGINS)

csv.lib: LIBNAME = csv
csv.lib: csv.o
csv: csv.o csv.lib
	@echo "Compiled library $@"

html.lib: LIBNAME = html
html.lib: html.o
html: html.o html.lib
	@echo "Compiled library $@"

text.lib: LIBNAME = text
text.lib: text.o
text: text.o text.lib
	@echo "Compiled library $@"

xml.lib: LIBNAME = xml
xml.lib: xml.o
xml: xml.o xml.lib
	@echo "Compiled library $@"

%.lib:
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