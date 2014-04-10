#!/bin/bash

ROOT_DIR=.
INC_DIR=include
SRC_DIR=src
TOOLS_DIR=$SRC_DIR
TESTS_DIR=tests
REPORTS_DIR=$TESTS_DIR/running_report


now=$(date +"%F_%H-%M")
arch=$(uname -m)
so=$(uname -s) # We use `-s` because `-o` is not supported on Mac OS X
so=${so#*/}
version=$(sed -n 's/^.*VERSION \"\([0-9]\.[0-9]*\)\"/\1/p' $INC_DIR/common.h)

test_build()
{
	. $TESTS_DIR/test_build.sh	
}

run_pepack()
{
    echo "--------- pepack ----------"
    if [ ! -d $REPORTS_DIR/pepack ]
    then
        mkdir $REPORTS_DIR/pepack
    fi
    echo -n "Testing pepack... "
    if $TOOLS_DIR/pepack $1 > $REPORTS_DIR/pepack/${now}_pepack_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f csv... "
    if $TOOLS_DIR/pepack -f csv $1 > $REPORTS_DIR/pepack/${now}_pepack_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f xml..."
    if $TOOLS_DIR/pepack -f xml $1 > $REPORTS_DIR/pepack/${now}_pepack_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f html... "
    if $TOOLS_DIR/pepack -f html $1 > $REPORTS_DIR/pepack/${now}_pepack_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pehash()
{
    echo "---------- pehash ----------"
    if [ ! -d $REPORTS_DIR/pehash ]
    then
        mkdir $REPORTS_DIR/pehash
    fi
    echo -n "Testing pehash... "
    if $TOOLS_DIR/pehash $1 > $REPORTS_DIR/pehash/${now}_pehash_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f csv... "
    if $TOOLS_DIR/pehash -f csv $1 > $REPORTS_DIR/pehash/${now}_pehash_f_cvs
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f xml... "
    if $TOOLS_DIR/pehash -f xml $1 > $REPORTS_DIR/pehash/${now}_pehash_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f html... "
    if $TOOLS_DIR/pehash -f html $1 > $REPORTS_DIR/pehash/${now}_pehash_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -h dos... "
    if $TOOLS_DIR/pehash -h dos $1 > $REPORTS_DIR/pehash/${now}_pehash_h_dos
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -a sha512... "
    if $TOOLS_DIR/pehash -a sha512 $1 > $REPORTS_DIR/pehash/${now}_pehash_a_sha512
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -s '.text'... "
    if $TOOLS_DIR/pehash -s '.text' $1 > $REPORTS_DIR/pehash/${now}_pehash_s_text
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash --section-index 1... "
    if $TOOLS_DIR/pehash --section-index 1 $1 > $REPORTS_DIR/pehash/${now}_pehash_section-index_1
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pescan()
{
    echo "---------- pescan ----------"
    if [ ! -d $REPORTS_DIR/pescan ]
    then
        mkdir $REPORTS_DIR/pescan
    fi
    echo -n "Testing pescan... "
    if $TOOLS_DIR/pescan $1 > $REPORTS_DIR/pescan/${now}_pescan_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f csv... "
    if $TOOLS_DIR/pescan -f csv $1 > $REPORTS_DIR/pescan/${now}_pescan_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f xml... "
    if $TOOLS_DIR/pescan -f xml $1 > $REPORTS_DIR/pescan/${now}_pescan_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f html... "
    if $TOOLS_DIR/pescan -f html $1 > $REPORTS_DIR/pescan/${now}_pescan_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -v... "
    if $TOOLS_DIR/pescan -v $1 > $REPORTS_DIR/pescan/${now}_pescan_v
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pestr()
{

    echo "---------- pestr ----------"
    if [ ! -d $REPORTS_DIR/pestr ]
    then
        mkdir $REPORTS_DIR/pestr
    fi
    echo -n "Testing pestr ... "
    if $TOOLS_DIR/pestr $1 > $REPORTS_DIR/pestr/${now}_pestr_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -n 5 ... "
    if $TOOLS_DIR/pestr -n 5 $1 > $REPORTS_DIR/pestr/${now}_pestr_n_5
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -o ... "
    if $TOOLS_DIR/pestr -o $1 > $REPORTS_DIR/pestr/${now}_pestr_o
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -s ... "
    if $TOOLS_DIR/pestr -s $1 > $REPORTS_DIR/pestr/${now}_pestr_s
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr --net ... "
    if $TOOLS_DIR/pestr --net $1 > $REPORTS_DIR/pestr/${now}_pestr_net
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_peres()
{
    echo "---------- peres ----------"
    if [ ! -d $REPORTS_DIR/peres ]
    then
        mkdir $REPORTS_DIR/peres
    fi
    echo -n "Testing peres -i ... "
    if $TOOLS_DIR/peres -i $1 > $REPORTS_DIR/peres/${now}_peres_i
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -s ... "
    if $TOOLS_DIR/peres -s $1 > $REPORTS_DIR/peres/${now}_peres_s
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -x ... "
    if $TOOLS_DIR/peres -x $1 > $REPORTS_DIR/peres/${now}_peres_x
    then 
        if [ -d resources ]
        then
            echo "OK"
            rm -rf resources
        else
            echo "binary returns OK, but no resource was extracted"
        fi
    else
        echo "NOK"
    fi
    echo -n "Testing peres -a ... "
    if $TOOLS_DIR/peres -a $1 > $REPORTS_DIR/peres/${now}_peres_a
    then 
        if [ -d resources ]
        then
            echo "OK"
            rm -rf resources
        else
            echo "binary returns OK, but no resource was extracted"
        fi
    else
        echo "NOK"
    fi
}
run_pesec()
{
    echo "---------- pesec ----------"
    if [ ! -d $REPORTS_DIR/pesec ]
    then
        mkdir $REPORTS_DIR/pesec
    fi
    echo -n "Testing pesec... "
    if $TOOLS_DIR/pesec $1 > $REPORTS_DIR/pesec/${now}_pesec_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f csv... "
    if $TOOLS_DIR/pesec -f csv $1 > $REPORTS_DIR/pesec/${now}_pesec_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f xml... "
    if $TOOLS_DIR/pesec -f xml $1 > $REPORTS_DIR/pesec/${now}_pesec_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f html... "
    if $TOOLS_DIR/pesec -f html $1 > $REPORTS_DIR/pesec/${now}_pesec_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -c pem... "
    if $TOOLS_DIR/pesec -c pem $1 > $REPORTS_DIR/pesec/${now}_pesec_c_pem
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -o tmp_cert... "
    if $TOOLS_DIR/pesec -o tmp_cert $1 > $REPORTS_DIR/pesec/${now}_pesec_o_tmp_cert
    then 
        if [ -f tmp_cert -a -s tmp_cert ]
        then
            echo "OK"
        else
            echo "Command returns OK but don't export the cert to file."
        fi
    rm tmp_cert
    else
        echo "NOK"
    fi
}

run_readpe()
{

    echo "---------- readpe ----------"
    if [ ! -d $REPORTS_DIR/readpe ]
    then
        mkdir $REPORTS_DIR/readpe
    fi
    echo -n "Testing readpe... "
    if $TOOLS_DIR/readpe $1 > $REPORTS_DIR/readpe/${now}_readpe_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f csv... "
    if $TOOLS_DIR/readpe -f csv $1 > $REPORTS_DIR/readpe/${now}_readpe_f_cvs
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f xml... "
    if $TOOLS_DIR/readpe -f xml $1 > $REPORTS_DIR/readpe/${now}_readpe_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f html... "
    if $TOOLS_DIR/readpe -f html $1 > $REPORTS_DIR/readpe/${now}_readpe_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -H ... "
    if $TOOLS_DIR/readpe -H $1 > $REPORTS_DIR/readpe/${now}_readpe_H
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -S ... "
    if $TOOLS_DIR/readpe -S $1 > $REPORTS_DIR/readpe/${now}_readpe_S
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -d ... "
    if $TOOLS_DIR/readpe -d $1 > $REPORTS_DIR/readpe/${now}_readpe_d
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -h dos ... "
    if $TOOLS_DIR/readpe -h dos $1 > $REPORTS_DIR/readpe/${now}_readpe_h_dos
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -i ... "
    if $TOOLS_DIR/readpe -i $1 > $REPORTS_DIR/readpe/${now}_readpe_i
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -e ... "
    if $TOOLS_DIR/readpe -e $1 > $REPORTS_DIR/readpe/${now}_readpe_e
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

test_pe32()
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

test_pe64()
{
	echo 'coming soon...'
}

clean()
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
	*)
        echo "illegal option -- $1"
		echo "usage: run.sh <option>"
        echo "       run.sh clean"
        echo "       run.sh build"
        echo "       run.sh pe32 <binary_file_for_testing>"
        echo "       run.sh pe64 <binary_file_to_testing>"
		exit 1 ;;
esac
