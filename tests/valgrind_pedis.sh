#!/bin/bash

prog="valgrind -q ../src/build/pedis"
samples=../support_files/samples/*

n=0
err=0
for sample in $samples; do

	echo -e "\n$sample"

	func=$(../src/build/readpe -f csv "$sample" | grep Entry | cut -d, -f2)

	for format in text csv xml html; do
		$prog -f $format -r $func $sample > /dev/null 2>&1 || let err++
	done

	let n++
done

echo "$n samples analyzed. $err errors." > /dev/fd/2
