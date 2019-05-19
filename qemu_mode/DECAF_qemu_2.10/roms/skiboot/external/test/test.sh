#! /bin/sh

# Copyright 2013-2014 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

run_binary() {
	if [ -x "$1" ] ; then
		$VALGRIND "$1" $2 2>> $STDERR_OUT 1>> $STDOUT_OUT
	else
		echo "Fatal error, cannot execute binary '$1'. Did you make?";
		exit 1;
	fi
}

fail_test() {
	rm -rf "$STDERR_OUT";
	rm -rf "$STDOUT_OUT";
	echo "$0 ($CUR_TEST): test failed";
	exit ${1:-1};
}

pass_test() {
	/bin/true;
}

strip_version_from_result() {
	VERSION=$(./make_version.sh $1)
	sed -i "s/${VERSION}/VERSION/" $STDERR_OUT
	sed -i "s/${VERSION}/VERSION/" $STDOUT_OUT
}

diff_with_result() {
	# Explicitly diff a file with an arbitrary result file
	if [ "$#" -eq 1 ] ; then
		if ! diff -u "$RESULT" "$1" ; then
			fail_test;
		fi
	# Otherwise just diff result.out with stdout and result.err with stderr
	else
		if ! diff -u "${RESULT}.out" "$STDOUT_OUT" ; then
			fail_test;
		fi
		if ! diff -u "${RESULT}.err" "$STDERR_OUT" ; then
			fail_test;
		fi
	fi
}

run_tests() {
	if [ $# -ne 2 ] ; then
		echo "Usage run_tests test_dir result_dir";
		exit 1;
	fi

	all_tests="$1";
	res_path="$2";

	if [ ! -d "$res_path" ] ; then
		echo "Result path isn't a valid directory";
		exit 1;
	fi

	export STDERR_OUT=$(mktemp --tmpdir external-test-stderr.XXXXXX);
	export STDOUT_OUT=$(mktemp --tmpdir external-test-stdout.XXXXXX);


	for the_test in $all_tests; do
		export CUR_TEST=$(basename $the_test)
		export RESULT="$res_path/$CUR_TEST"

		. "$the_test";
		R="$?"
		if [ "$R" -ne 0 ] ; then
			fail_test "$R";
		fi
	#reset for next test
	> "$STDERR_OUT";
	> "$STDOUT_OUT";
	done

	rm -rf $STDERR_OUT;
	rm -rf $STDOUT_OUT;

	echo "$0 tests passed"

	exit 0;
}

