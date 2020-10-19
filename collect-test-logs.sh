#!/bin/bash

echo "Collecting test logs"
LOG_DIR=./
html="<html><h3>There are failed tests:</h3><table>"
logs=$(find $LOG_DIR -type f -iname "*.html" -print)
logs_found=0
for name in $logs
do
	logname=$(basename $name)
	testname=$(echo $logname | awk -F 'log_run-tests_' '{print $2}' | awk -F '.html' '{print $1}')
	echo $testname
	html+="<tr align=\"left\"><td><a href="$logname">$testname</a>"

	corefilesearch=/cores/core.*.!*!.libs!$testname.* ;
	echo $corefilesearch ;
	if ls $corefilesearch 1> /dev/null 2>&1; then
		echo "coredump found";
		coredump=$(ls $corefilesearch) ;
		echo $coredump;
		echo "set logging file $LOG_DIR/backtrace_${testname}.txt" ;
		gdb -ex "set logging file $LOG_DIR/backtrace_${testname}.txt" -ex "set logging on" -ex "set pagination off" -ex "bt full" -ex "bt" -ex "info threads" -ex "thread apply all bt" -ex "thread apply all bt full" -ex "quit" .libs/$testname $coredump ;
		ls -la $LOG_DIR
	fi ;


	backtrace="backtrace_$testname.txt"
	if test -f "${LOG_DIR}/$backtrace"; then
		html+=". Core dumped, backtrace is available <a href=\"$backtrace\">here</a>"
	fi
	html+="</td></tr>"
	logs_found=1
done

if [ $logs_found -ne 0 ]; then
	html+="</table></html>"
	echo $html > $LOG_DIR/artifacts.html
	exit 1
fi

exit 0