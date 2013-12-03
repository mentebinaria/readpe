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

#run_pescan()
#{
    
#}

run_pepack()
{
    echo "--------- pepack ----------"
    echo -n "Testing pepack... "
    if ../src/pepack $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f csv... "
    if ../src/pepack -f csv $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f xml..."
    if ../src/pepack -f xml $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pepack -f html... "
    if ../src/pepack -f html $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}
run_pehash()
{
    echo "---------- pehash ----------"
    echo -n "Testing pehash... "
    if ../src/pehash $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f csv... "
    if ../src/pehash -f csv $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f xml... "
    if ../src/pehash -f xml $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -f html... "
    if ../src/pehash -f html $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -h dos... "
    if ../src/pehash -h dos $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -a sha512... "
    if ../src/pehash -a sha512 $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash -s '.text'... "
    if ../src/pehash -s '.text' $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pehash --section-index 1... "
    if ../src/pehash --section-index 1 $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pescan()
{
    echo "---------- pescan ----------"
    echo -n "Testing pescan... "
    if ../src/pescan $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f csv... "
    if ../src/pescan -f csv $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f xml... "
    if ../src/pescan -f xml $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -f html... "
    if ../src/pescan -f html $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pescan -v... "
    if ../src/pescan -v $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_pestr()
{

    echo "---------- pestr ----------"
    echo -n "Testing pestr ... "
    if ../src/pestr $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -n 5 ... "
    if ../src/pestr -n 5 $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -o ... "
    if ../src/pestr -o $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr -s ... "
    if ../src/pestr -s $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing pestr --net ... "
    if ../src/pestr --net $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
}

run_peres()
{
    echo "---------- peres ----------"
    echo -n "Testing peres -i ... "
    if ../src/peres -i $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -s ... "
    if ../src/peres -s $1 > /dev/null
    then 
        echo "OK"
    else
        echo "NOK"
    fi
    echo -n "Testing peres -x ... "
    if ../src/peres -x $1 > /dev/null
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
    if ../src/peres -a $1 > /dev/null
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

test_pe32()
{
    run_pepack $1
    run_pehash $1
    run_pescan $1
    run_peres $1
    run_pestr $1
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
