#!/bin/bash

prog="valgrind -q ../src/pesec"
samples=../support_files/samples/*

n=0
err=0
for sample in $samples; do

	echo -e "\n$sample"

	for format in text csv xml html; do
			$prog -f $format $sample || let err++
	done

	let n++
done

echo "$n samples analyzed. $err errors." > /dev/fd/2
