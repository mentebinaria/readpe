LIBPE_DIR = lib/libpe
PEV_DIR = src
MAKE = make
VERSION = 0.60
ZIPFILE = pev-$(VERSION)-win32.zip

# simple call each separated Makefile
all:
%:
	cd $(LIBPE_DIR); $(MAKE) $@
	cd $(PEV_DIR); $(MAKE) $@

# zip rule only Cygwin targets
zip:
	zip -j $(ZIPFILE) lib/libpe/libpe.dll \
	/usr/bin/cygwin1.dll \
	/usr/bin/cygpcre-1.dll \
	/usr/bin/cygcrypto-1.0.0.dll /usr/bin/cygz.dll /usr/bin/cyggcc_s-1.dll \
	src/*.exe changelog license readme
