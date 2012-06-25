#!/bin/bash

prog="valgrind -q ../src/petls"
samples=samples/binary_corpus_v2/corkami/*

n=0
err=0
for sample in $samples; do

	echo -e "\n$sample"

	#for format in text csv xml html; do
			#$prog -f $format $sample || let err++
			$prog $sample || let err++
	#done

	let n++
done

echo "$n samples analyzed. $err errors." > /dev/fd/2
