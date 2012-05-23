LIBPE_DIR=lib/libpe
LIBMXML_DIR=lib/libmxml
PEV_DIR=src
MAKE=make
VERSION=0.50_alpha2
ZIPFILE=pev.zip

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
#	cd $(LIBMXML_DIR); ./configure; $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@


clean:
	cd $(LIBPE_DIR); $(MAKE) $@
#	cd $(LIBMXML_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@


install:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@


# zip rule only Cygwin targets
zip:
	zip -j $(ZIPFILE) lib/libpe/libpe.dll \
	src/*.exe AUTHORS CHANGELOG LICENSE README
