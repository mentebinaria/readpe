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

run_pepack()
{
    echo "--------- pepack ----------"
    if [ ! -d running_report/pepack ]
    then
        mkdir running_report/pepack
    fi
    echo -n "Testing pepack... "
    if ../src/pepack $1 > running_report/pepack/${now}_pepack_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f csv... "
    if ../src/pepack -f csv $1 > running_report/pepack/${now}_pepack_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f xml..."
    if ../src/pepack -f xml $1 > running_report/pepack/${now}_pepack_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f html... "
    if ../src/pepack -f html $1 > running_report/pepack/${now}_pepack_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pehash()
{
    echo "---------- pehash ----------"
    if [ ! -d running_report/pehash ]
    then
        mkdir running_report/pehash
    fi
    echo -n "Testing pehash... "
    if ../src/pehash $1 > running_report/pehash/${now}_pehash_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f csv... "
    if ../src/pehash -f csv $1 > running_report/pehash/${now}_pehash_f_cvs
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f xml... "
    if ../src/pehash -f xml $1 > running_report/pehash/${now}_pehash_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f html... "
    if ../src/pehash -f html $1 > running_report/pehash/${now}_pehash_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -h dos... "
    if ../src/pehash -h dos $1 > running_report/pehash/${now}_pehash_h_dos
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -a sha512... "
    if ../src/pehash -a sha512 $1 > running_report/pehash/${now}_pehash_a_sha512
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -s '.text'... "
    if ../src/pehash -s '.text' $1 > running_report/pehash/${now}_pehash_s_text
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash --section-index 1... "
    if ../src/pehash --section-index 1 $1 > running_report/pehash/${now}_pehash_section-index_1
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pescan()
{
    echo "---------- pescan ----------"
    if [ ! -d running_report/pescan ]
    then
        mkdir running_report/pescan
    fi
    echo -n "Testing pescan... "
    if ../src/pescan $1 > running_report/pescan/${now}_pescan_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f csv... "
    if ../src/pescan -f csv $1 > running_report/pescan/${now}_pescan_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f xml... "
    if ../src/pescan -f xml $1 > running_report/pescan/${now}_pescan_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f html... "
    if ../src/pescan -f html $1 > running_report/pescan/${now}_pescan_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -v... "
    if ../src/pescan -v $1 > running_report/pescan/${now}_pescan_v
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pestr()
{

    echo "---------- pestr ----------"
    if [ ! -d running_report/pestr ]
    then
        mkdir running_report/pestr
    fi
    echo -n "Testing pestr ... "
    if ../src/pestr $1 > running_report/pestr/${now}_pestr_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -n 5 ... "
    if ../src/pestr -n 5 $1 > running_report/pestr/${now}_pestr_n_5
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -o ... "
    if ../src/pestr -o $1 > running_report/pestr/${now}_pestr_o
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -s ... "
    if ../src/pestr -s $1 > running_report/pestr/${now}_pestr_s
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr --net ... "
    if ../src/pestr --net $1 > running_report/pestr/${now}_pestr_net
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_peres()
{
    echo "---------- peres ----------"
    if [ ! -d running_report/peres ]
    then
        mkdir running_report/peres
    fi
    echo -n "Testing peres -i ... "
    if ../src/peres -i $1 > running_report/peres/${now}_peres_i
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -s ... "
    if ../src/peres -s $1 > running_report/peres/${now}_peres_s
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -x ... "
    if ../src/peres -x $1 > running_report/peres/${now}_peres_x
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
    if ../src/peres -a $1 > running_report/peres/${now}_peres_a
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
    if [ ! -d running_report/pesec ]
    then
        mkdir running_report/pesec
    fi
    echo -n "Testing pesec... "
    if ../src/pesec $1 > running_report/pesec/${now}_pesec_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f csv... "
    if ../src/pesec -f csv $1 > running_report/pesec/${now}_pesec_f_csv
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f xml... "
    if ../src/pesec -f xml $1 > running_report/pesec/${now}_pesec_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -f html... "
    if ../src/pesec -f html $1 > running_report/pesec/${now}_pesec_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -c pem... "
    if ../src/pesec -c pem $1 > running_report/pesec/${now}_pesec_c_pem
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pesec -o tmp_cert... "
    if ../src/pesec -o tmp_cert $1 > running_report/pesec/${now}_pesec_o_tmp_cert
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
    if [ ! -d running_report/readpe ]
    then
        mkdir running_report/readpe
    fi
    echo -n "Testing readpe... "
    if ../src/readpe $1 > running_report/readpe/${now}_readpe_default
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f csv... "
    if ../src/readpe -f csv $1 > running_report/readpe/${now}_readpe_f_cvs
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f xml... "
    if ../src/readpe -f xml $1 > running_report/readpe/${now}_readpe_f_xml
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -f html... "
    if ../src/readpe -f html $1 > running_report/readpe/${now}_readpe_f_html
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -H ... "
    if ../src/readpe -H $1 > running_report/readpe/${now}_readpe_H
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -S ... "
    if ../src/readpe -S $1 > running_report/readpe/${now}_readpe_S
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -d ... "
    if ../src/readpe -d $1 > running_report/readpe/${now}_readpe_d
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -h dos ... "
    if ../src/readpe -h dos $1 > running_report/readpe/${now}_readpe_h_dos
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -i ... "
    if ../src/readpe -i $1 > running_report/readpe/${now}_readpe_i
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing readpe -e ... "
    if ../src/readpe -e $1 > running_report/readpe/${now}_readpe_e
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

test_pe32()
{
    if [ ! -d running_report ]
    then
        mkdir running_report
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

case "$1" in
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
		echo 'tell me what to do...'
		exit 1 ;;
esac
