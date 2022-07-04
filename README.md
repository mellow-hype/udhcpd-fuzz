# udhcpd fuzzing

blog post: [fuzzing udhcpd](https://blog.coffinsec.com/fuzzing/2022/06/05/fuzzing-udhcpd.html)

## harness
- customized version of udhcpd using AFL LLVM persistent mode 
- reads from stdin
- build: `cd harness1/src && CC=afl-clang-fast make`
- fuzz: `afl-fuzz -i inputs/ -o outputs/ -- ./udhcpd-harness`

## testcase generator
- `corpus-gen/`
- modified version of udhcpc that generates DHCP packet objects and writes the bytes to files
- build: `cd corpus-gen/src && make`
- run: `mkdir corpus && cp mk-testcases corpus && cd corpus && ./mk-testcases && rm mk-testcases`
