#!/bin/bash

current_dir=$PWD

work_dir=./
cd $work_dir

nproc --all
make -j`nproc --ignore=1` check

TEST_RESULTS=$(ls *trs)

for i in $TEST_RESULTS
do
	TEST=$(basename $i .trs)
	if grep -q "test-result: FAIL" "$TEST.trs"; then
		logfilename="log_run-tests_$TEST.html";
		cat ./"$TEST.log" | tee >(ansi2html > $logfilename) ;
	fi ;
done

cd $current_dir
