#!/bin/bash

prog="valgrind -q ../src/pedis"
samples=../support_files/samples/*

n=0
err=0
for sample in $samples; do

	echo -e "\n$sample"

	func=$(../src/readpe -f csv -h optional "$sample" | grep Entry | cut -d, -f2)

	for format in text csv xml html; do
			$prog -f $format -F $func $sample || let err++
	done

	let n++
done

echo "$n samples analyzed. $err errors." > /dev/fd/2
