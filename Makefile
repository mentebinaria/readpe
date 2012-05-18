LIBPE_DIR=lib/libpe
PEV_DIR=src
MAKE=make
VERSION=0.50

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@

# zip rule only Cygwin targets
zip:
	zip -rj pev-$(VERSION)-win.zip lib/libpe/libpe.dll \
	src/ AUTHORS CHANGELOG LICENSE README -x *.c *.h
