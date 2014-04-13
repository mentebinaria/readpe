LIBPE_DIR = lib/libpe
PEV_DIR = src
MAKE = make
VERSION = 0.71
ZIPFILE = pev-$(VERSION)-win32.zip

all:
%:
	cd $(LIBPE_DIR) && $(MAKE) $@
	cd $(PEV_DIR) && $(MAKE) $@

# Cygwin only
zip:
	mkdir -p pevwin/plugins
	cp src/build/plugins/*.dll pevwin/plugins/
	echo 'plugins_dir=plugins' > pevwin/pev.conf
	cp lib/libpe/libpe.dll pevwin/
	cp /usr/bin/cygwin1.dll pevwin/
	cp /usr/bin/cygcrypto-1.0.0.dll pevwin/
	cp /usr/bin/cygz.dll pevwin/
	cp README.md pevwin/
	cp src/build/*.exe pevwin/
	zip -jr $(ZIPFILE) pevwin
	rm -rf pevwin