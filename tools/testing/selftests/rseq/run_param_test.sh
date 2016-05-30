#!/bin/bash

EXTRA_ARGS=${@}

OLDIFS="$IFS"
IFS=$'\n'
TEST_LIST=(
	"-T s"
	"-T l"
	"-T b"
	"-T b -M"
	"-T m"
	"-T m -M"
	"-T i"
)

TEST_NAME=(
	"spinlock"
	"list"
	"buffer"
	"buffer with barrier"
	"memcpy"
	"memcpy with barrier"
	"increment"
)
IFS="$OLDIFS"

function do_tests()
{
	local i=0
	while [ "$i" -lt "${#TEST_LIST[@]}" ]; do
		echo "Running test ${TEST_NAME[$i]}"
		./param_test ${TEST_LIST[$i]} ${@} ${EXTRA_ARGS} || exit 1
		let "i++"
	done
}

echo "Default parameters"
do_tests

echo "Loop injection: 10000 loops"

OLDIFS="$IFS"
IFS=$'\n'
INJECT_LIST=(
	"1"
	"2"
	"3"
	"4"
	"5"
	"6"
	"7"
	"8"
	"9"
)
IFS="$OLDIFS"

NR_LOOPS=10000

i=0
while [ "$i" -lt "${#INJECT_LIST[@]}" ]; do
	echo "Injecting at <${INJECT_LIST[$i]}>"
	do_tests -${INJECT_LIST[i]} ${NR_LOOPS}
	let "i++"
done
NR_LOOPS=

function inject_blocking()
{
	OLDIFS="$IFS"
	IFS=$'\n'
	INJECT_LIST=(
		"7"
		"8"
		"9"
	)
	IFS="$OLDIFS"

	NR_LOOPS=-1

	i=0
	while [ "$i" -lt "${#INJECT_LIST[@]}" ]; do
		echo "Injecting at <${INJECT_LIST[$i]}>"
		do_tests -${INJECT_LIST[i]} -1 ${@}
		let "i++"
	done
	NR_LOOPS=
}

echo "Yield injection (25%)"
inject_blocking -m 4 -y -r 100

echo "Yield injection (50%)"
inject_blocking -m 2 -y -r 100

echo "Yield injection (100%)"
inject_blocking -m 1 -y -r 100

echo "Kill injection (25%)"
inject_blocking -m 4 -k -r 100

echo "Kill injection (50%)"
inject_blocking -m 2 -k -r 100

echo "Kill injection (100%)"
inject_blocking -m 1 -k -r 100

echo "Sleep injection (1ms, 25%)"
inject_blocking -m 4 -s 1 -r 100

echo "Sleep injection (1ms, 50%)"
inject_blocking -m 2 -s 1 -r 100

echo "Sleep injection (1ms, 100%)"
inject_blocking -m 1 -s 1 -r 100

echo "Disable rseq for 25% threads"
do_tests -D 4

echo "Disable rseq for 50% threads"
do_tests -D 2

echo "Disable rseq"
do_tests -d
