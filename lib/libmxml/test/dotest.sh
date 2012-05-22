#!/bin/sh
(cd ..; make mxmldoc-static)

files=""
mode=""

while test $# -gt 0; do
	arg="$1"
	shift

	case "$arg" in
		-f) framed="--framed framed" ;;
		-g) mode="gdb" ;;
		-v) mode="valgrind" ;;
		*.h | *.c | *.cxx) files="$files $arg" ;;
		*)
			echo "Usage: ./dotest.sh [-f] [-g] [-v] [files]"
			exit 1
			;;
	esac
done

if test "$files" = ""; then
	files=*.cxx
fi

rm -f test.xml

case "$mode" in
	gdb)
		echo "break malloc_error_break" >.gdbcmds
		echo "set env DYLD_INSERT_LIBRARIES /usr/lib/libgmalloc.dylib" >>.gdbcmds
		echo "run $framed test.xml $files >test.html 2>test.log" >>.gdbcmds
		gdb -x .gdbcmds ../mxmldoc-static
		;;

	valgrind)
		valgrind --log-fd=3 --leak-check=yes \
			../mxmldoc-static $framed test.xml $files \
			>test.html 2>test.log 3>test.valgrind
		;;

	*)
		../mxmldoc-static $framed test.xml $files >test.html 2>test.log
		;;
esac

