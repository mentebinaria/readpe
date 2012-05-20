#!/bin/bash

report=${now}_${arch}_$(basename $0 .sh).log

report()
{
	if [ -z "$1" ]; then
		while read l; do
			echo "$l" >> $report
		done <&0
		echo >> $report
	else
		echo -e "$1\n" >> $report;
	fi
}

report_status() { [ "$1" -eq 0 ] && report '>>> SUCCESS' || report '>>> FAILED'; }

cd ..
report \
"pev test report
----------------
Type: $(basename $0 .sh)
Date: $now
Arch: $arch
Version: $version"

echo -n "Configuring for $arch... "
./configure | report
pipe=${PIPESTATUS[0]}
[ "$pipe" -eq 0 ] && echo ok || echo failed
report_status $pipe

echo -n "Compiling... "
make 2>&1 | report
pipe=${PIPESTATUS[0]}
[ "$pipe" -eq 0 ] && echo ok || echo failed
report_status $pipe

mv "$report" tests/
cd tests

echo -e "\nReport: $report, $(wc -l $report | cut -d' ' -f1) lines, \
$(ls -lh $report | cut -d' ' -f5)."
