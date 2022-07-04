
## Requirements

Uses AFLPlusPlus, requires `afl-clang-fast` for persistent mode

## Build

Normal:

```
CC=afl-clang-fast make && make install
```

ASAN:
```
AFL_USE_ASAN=1 CC=afl-clang-fast make && make install
```

Automatic:
```
./rebuild.sh
```

Binaries will be saved to `bin/`.

## Fuzzing

Use this script to set up a directory for the new fuzzing run with the testcases, conf file, and harness binary inside:

```
./init_run.sh
```

```
afl-fuzz -i testcases -o outs -- ./udhcpd-harness
afl-fuzz -i testcases -o outs -- ./udhcpd-harness_asan
```