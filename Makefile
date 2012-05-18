LIBPE_DIR=lib/libpe
PEV_DIR=src
MAKE=make
VERSION=0.50_alpha2
ZIPFILE=pev-$(VERSION)_x86.zip

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@

# zip rule only Cygwin targets
zip:
	zip -rj $(ZIPFILE) lib/libpe/libpe.dll \
	src/ AUTHORS CHANGELOG LICENSE README -x *.c *.h Makefile
