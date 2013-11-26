#!/bin/bash

now=$(date +"%F_%H-%M")
arch=$(uname -m)
so=$(uname -o)
so=${so#*/}
version=$(sed -n 's/^.*VERSION \"\([0-9]\.[0-9]*\)\"/\1/p' ../src/common.h)

test_build()
{
	. test_build.sh	
}

test_pe32()
{
	echo 'coming soon...'
}

test_pe64()
{
	echo 'coming soon...'
}

case "$1" in
	"build")
		test_build ;;
	"pe32")
		test_pe32 ;;
	"pe64")
		test_pe64 ;;
	*)
		echo 'tell me what to do...'
		exit 1 ;;
esac
