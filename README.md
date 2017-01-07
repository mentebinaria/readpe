# pev

pev is a full-featured, open source, multiplatform command line toolkit to work with PE (Portable Executables) binaries.

This is the current source for a likely unreleased version. Use at your own risk. For more information and stable releases, please refer to http://pev.sourceforge.net/

[![Build Status](https://travis-ci.org/merces/pev.png)](https://travis-ci.org/merces/pev)

## How to get the source code?

	git clone --recursive https://github.com/merces/pev.git

## How to build on Linux?

	cd pev
	make

**NOTE**: You may need to install OpenSSL using your package manager. Examples:

	apt-get install libssl-dev
	yum install openssl-devel

## How to build on OS X?

	cd pev
	CFLAGS="-I/usr/local/opt/openssl/include/" LDFLAGS="-L/usr/local/opt/openssl/lib/" make

**NOTE**: You may need to install OpenSSL via [Homebrew](http://brew.sh/):

	brew update
	brew install openssl
	brew link --force openssl

## How to build on Windows (via [Cygwin](http://cygwin.com/))?

	cd pev
	make
	make zip

**NOTE**: The following packages must be installed along with your Cygwin:

	- gcc-core
	- binutils
	- make
	- zip
	- openssl-devel
	- git (just to clone de repository and make things easier)

Please check the [online documentation](http://pev.sourceforge.net/doc/manual/en_us) for more details.
