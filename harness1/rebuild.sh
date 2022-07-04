#!/bin/bash
COMPILER=afl-clang-fast

if [[ ! -z "$CC" ]]; then
    COMPILER=$CC
fi

echo "using compiler: $COMPILER"
# exit

echo "making normal build"
make clean && CC=$COMPILER make && make install

if [[ ! -z "$CC" ]]; then
    COMPILER=$CC
fi

echo "using compiler: $COMPILER"
# exit

echo "making ASAN build"
export AFL_USE_ASAN=1
make clean && CC=$COMPILER make && make install
unset AFL_USE_ASAN
