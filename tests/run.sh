#!/bin/bash

ROOT_DIR=.
INC_DIR=include
SRC_DIR=src
TOOLS_DIR=$SRC_DIR/build
TESTS_DIR=tests
REPORTS_DIR=$TESTS_DIR/running_report
EXPECTED_OUTPUTS_DIR=$TESTS_DIR/expected_outputs
SUPPORTED_FORMATS="csv html json text xml"
BINDIFF=$(which diff)

now=$(date +"%F_%H-%M")
arch=$(uname -m)
so=$(uname -s) # We use `-s` because `-o` is not supported on Mac OS X
so=${so#*/}
version=$(sed -n 's/^.*VERSION \"\([0-9]\.[0-9]*\)\"/\1/p' $INC_DIR/common.h)

function test_build
{
	. $TESTS_DIR/test_build.sh
}

function test_binary
{
	local onsuccess=$1; shift;
	local onfailure=$1; shift;
	local logname=$1; shift;
	local binname=$1; shift;
	local args=$*

	if [ ! -d $REPORTS_DIR/${binname} ]
	then
		mkdir -p $REPORTS_DIR/${binname}
	fi

	echo -n "Testing ${binname} ${args}... "
	if $TOOLS_DIR/${binname} ${args} > "$REPORTS_DIR/${binname}/${now}_${binname}_${logname}.txt"
	then
		eval ${onsuccess}
	else
		eval ${onfailure}
		return # Stop at error
	fi
}

function test_binary_using_all_formats
{
	local onsuccess=$1; shift;
	local onfailure=$1; shift;
	local logname=$1; shift;
	local binname=$1; shift;
	local args=$*

	# First run using the default output format.
	test_binary "${onsuccess}" "${onfailure}" "${logname}" ${binname} ${args}

	# Then run using every supported output format.
	for format in $SUPPORTED_FORMATS
	do
		echo -n "Testing ${binname} -f ${format} ${args}... "
		if $TOOLS_DIR/${binname} -f ${format} ${args} > "$REPORTS_DIR/${binname}/${now}_${binname}_${logname}_${format}.txt"
		then
			eval ${onsuccess}
		else
			eval ${onfailure}
			break # Stop at 1st error
		fi
	done
}

function test_binary_output_against_expected_output
{
	local onsuccess=$1; shift;
	local onfailure=$1; shift;
	local logname=$1; shift;
	local binname=$1; shift;
	local binsample=$1; shift;
	local args=$*;
	local reported_output="$EXPECTED_OUTPUTS_DIR/_tmp/${binsample}/${binname}_${logname}.txt";
	local expected_output_ok="$EXPECTED_OUTPUTS_DIR/${binsample}/${binname}_${logname}.txt";
	local expected_output_fail="$EXPECTED_OUTPUTS_DIR/${binsample}/${binname}_${logname}_fail.txt";

	if [ ! -d $EXPECTED_OUTPUTS_DIR/_tmp/${binsample} ]
	then
		mkdir -p $EXPECTED_OUTPUTS_DIR/_tmp/${binsample}
	fi

	echo -n "Running $TOOLS_DIR/${binname} -f json ${args} ${binsample} &> \"${reported_output}\"... "
	$TOOLS_DIR/${binname} -f json ${args} ${binsample} &> "${reported_output}"
	local ret="$?"
	echo "ret=$ret"

	if [ "$ret" -eq "0" ]
	then
		expected_output=${expected_output_ok}
	else
		expected_output=${expected_output_fail}
	fi

	echo -n "Comparing \"${expected_output}\" against \"${reported_output}\"... "
	${BINDIFF} -u "${expected_output}" "${reported_output}" &> /dev/null
	ret="$?"

	if [ "$ret" -eq "0" ]
	then
		eval ${onsuccess}
	else
		eval ${onfailure}
		#echo "Showing differences:"
		#head -n 5 tmp.diff
		return # Stop at error
	fi
}

function run_pepack
{
	local binname=pepack
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary_using_all_formats "echo OK" "echo NOK" "default"            ${binname} ${args}
}

function run_pehash
{
	local binname=pehash
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary_using_all_formats "echo OK" "echo NOK" "default"            ${binname} ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "h_dos"              ${binname} -h dos ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "a_sha512"           ${binname} -a sha512 ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "s_text"             ${binname} -s '.text' ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "section_index_1"    ${binname} --section-index 1 ${args}
}

function run_pescan
{
	local binname=pescan
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary_using_all_formats "echo OK" "echo NOK" "default"    ${binname} ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "v"          ${binname} -v ${args}
}

function run_pestr
{
	local binname=pestr
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary "echo OK" "echo NOK" "default"  ${binname} ${args}
	test_binary "echo OK" "echo NOK" "n_5"      ${binname} -n 5 ${args}
	test_binary "echo OK" "echo NOK" "o"        ${binname} -o ${args}
	test_binary "echo OK" "echo NOK" "s"        ${binname} -s ${args}
}

function peres_on_success
{
	if [ -d resources ]
	then
		echo "OK"
		rm -rf resources
	else
		echo "binary returns OK, but no resource was extracted"
	fi
}

function run_peres
{
	local binname=peres
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary "echo OK"        "echo NOK" "i" ${binname} -i ${args}
	test_binary "echo OK"        "echo NOK" "s" ${binname} -s ${args}
	test_binary peres_on_success "echo NOK" "x" ${binname} -x ${args}
	test_binary peres_on_success "echo NOK" "a" ${binname} -a ${args}
}

function pesec_on_success
{
	if [ -f tmp_cert -a -s tmp_cert ]
	then
		echo "OK"
	else
		echo "Command returns OK but don't export the cert to file."
	fi
	rm tmp_cert
}

function run_pesec
{
	local binname=pesec
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary_using_all_formats "echo OK"         "echo NOK" "default"    ${binname} ${args}
	test_binary_using_all_formats "echo OK"         "echo NOK" "c_pem"      ${binname} -c pem ${args}
	test_binary_using_all_formats pesec_on_success  "echo NOK" "o_tmp_cert" ${binname} -o tmp_cert ${args}
}

function run_readpe
{
	local binname=readpe
	local args=$*
	echo "---------- ${binname} ----------"
	test_binary_using_all_formats "echo OK" "echo NOK" "default"    ${binname} ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "H"          ${binname} -H ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "S"          ${binname} -S ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "d"          ${binname} -d ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "h_dos"      ${binname} -h dos ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "i"          ${binname} -i ${args}
	test_binary_using_all_formats "echo OK" "echo NOK" "e"          ${binname} -e ${args}
}

function test_regression
{
	if [ ! -d $EXPECTED_OUTPUTS_DIR ]
	then
		mkdir -p $EXPECTED_OUTPUTS_DIR
	fi

	local binsample="$1"

	test_binary_output_against_expected_output "echo OK" "echo NOK" "default"           pepack ${binsample}

	test_binary_output_against_expected_output "echo OK" "echo NOK" "default"           pehash ${binsample}
	test_binary_output_against_expected_output "echo OK" "echo NOK" "h_dos"             pehash ${binsample} -h dos
	test_binary_output_against_expected_output "echo OK" "echo NOK" "a_sha512"          pehash ${binsample} -a sha512
	test_binary_output_against_expected_output "echo OK" "echo NOK" "s_text"            pehash ${binsample} -s '.text'
	test_binary_output_against_expected_output "echo OK" "echo NOK" "section_index_1"   pehash ${binsample} --section-index 1

	test_binary_output_against_expected_output "echo OK" "echo NOK" "default"           pescan ${binsample}
	test_binary_output_against_expected_output "echo OK" "echo NOK" "v"                 pescan ${binsample} -v

	test_binary_output_against_expected_output "echo OK" "echo NOK" "i"                 peres ${binsample} -i
	test_binary_output_against_expected_output "echo OK" "echo NOK" "s"                 peres ${binsample} -s
	test_binary_output_against_expected_output "echo OK" "echo NOK" "x"                 peres ${binsample} -x
	test_binary_output_against_expected_output "echo OK" "echo NOK" "a"                 peres ${binsample} -a

	test_binary_output_against_expected_output "echo OK" "echo NOK" "default"           pesec ${binsample}
	test_binary_output_against_expected_output "echo OK" "echo NOK" "c_pem"             pesec ${binsample} -c pem
	test_binary_output_against_expected_output "echo OK" "echo NOK" "o_tmp_cert"        pesec ${binsample} -o tmp_cert

	test_binary_output_against_expected_output "echo OK" "echo NOK" "default"           readpe ${binsample}
	test_binary_output_against_expected_output "echo OK" "echo NOK" "H"                 readpe ${binsample} -H
	test_binary_output_against_expected_output "echo OK" "echo NOK" "S"                 readpe ${binsample} -S
	test_binary_output_against_expected_output "echo OK" "echo NOK" "d"                 readpe ${binsample} -d
	test_binary_output_against_expected_output "echo OK" "echo NOK" "h_dos"             readpe ${binsample} -h dos
	test_binary_output_against_expected_output "echo OK" "echo NOK" "i"                 readpe ${binsample} -i
	test_binary_output_against_expected_output "echo OK" "echo NOK" "e"                 readpe ${binsample} -e
}

function test_pe32
{
	if [ ! -d $REPORTS_DIR ]
	then
		mkdir -p $REPORTS_DIR
	fi

	run_pepack $1
	run_pehash $1
	run_pescan $1
	run_peres $1
	run_pestr $1
	run_pesec $1
	run_readpe $1
}   

function test_pe64
{
	echo 'coming soon...'
}

function clean
{
	if [ -d $REPORTS_DIR ]
	then
		rm -rf $REPORTS_DIR
	fi

	rm -rf $TESTS_DIR/*.log
}

case "$1" in
	"clean")
		clean ;;
	"build")
		test_build ;;
	"pe32")
		if [ $# -ne 2 ]
		then
			echo "missing argument: use $0 pe32 <binary file>"
		else
			test_pe32 $2
		fi
		;;
	"pe64")
		test_pe64 ;;
	"regression")
		if [ $# -ne 2 ]
		then
			echo "missing argument: use $0 regression <binary file>"
		else
			test_regression $2
		fi
		;;
	*)
		echo "illegal option -- $1"
		echo "usage: run.sh <option>"
		echo "       run.sh clean"
		echo "       run.sh build"
		echo "       run.sh pe32 <binary_file_for_testing>"
		echo "       run.sh pe64 <binary_file_to_testing>"
		echo "       run.sh regression <binary_file_for_testing>"
		exit 1 ;;
esac
