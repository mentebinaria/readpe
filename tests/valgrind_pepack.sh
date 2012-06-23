#!/bin/bash

prog="valgrind -q ../src/pepack"
samples=../support_files/samples/*

n=0
err=0
for sample in $samples; do

	echo -e "\n$sample"
	$prog $sample || let err++
	let n++
done

echo "$n samples analyzed. $err errors." > /dev/fd/2
