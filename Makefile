LIBPE_DIR=lib/libpe
PEV_DIR=src
MAKE=make

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@
