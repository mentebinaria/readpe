LIBPE_DIR=lib/libpe
PEV_DIR=src
MAKE=make
VERSION=0.50
ZIPFILE=pev.zip

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@

# zip rule only Cygwin targets
zip:
	zip -j $(ZIPFILE) lib/libpe/libpe.dll \
	src/*.exe AUTHORS CHANGELOG LICENSE README
